"""Security invariants, including HTTP routing and execution side effects.

Runs offline, with temporary keys/logs and no browser or model API calls:
    python -B -m unittest discover -s tests -p test_security_hardening.py -v
"""
import asyncio
import copy
import json
import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from gateway import config
from gateway import server as gs
from gateway.api_schema import (Action, AuthorizeRequest, CapabilityDeclaration,
    ConfirmRequest, ConsumeRequest, ToolRegistrationRequest)
from attestation.signer import Signer
from attestation.log import CertificateLog
from policy.capability_registry import CapabilityRegistry
from policy.engine import PolicyEngine
from policy.paths import within_envelope
from policy import taint, symbolic
from adapters.sdk import ICBGuardClient, AuthorizeResult, AuthorizationBlocked, guard


def rule(tool, value, field="target"):
    return {"tool": tool, "decision": "allow", "predicate": {"op": "eq", "field": field, "value": value}}


async def http_call(path, body=None, token="", method="POST"):
    """Exercise real ASGI routing/dependencies without an HTTP client dependency."""
    data = json.dumps(body or {}).encode()
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
             "query_string": b"", "headers": [(b"content-type", b"application/json"),
                (b"authorization", ("Bearer " + token).encode())],
             "server": ("test", 80), "client": ("127.0.0.1", 1234)}
    messages = []
    async def receive():
        return {"type": "http.request", "body": data, "more_body": False}
    async def send(message):
        messages.append(message)
    await gs.app(scope, receive, send)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    content = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(content or b"{}")


class SecurityHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="icb-security-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.allowed = self.root / "allowed"
        self.allowed.mkdir()
        self.path = str(self.allowed / "one.txt")
        self.other = str(self.allowed / "two.txt")
        self.signer = Signer(self.root / "key.pem", self.root / "key.pub")
        self.patches = [patch.object(config, "DEV_MODE", True),
            patch.object(config, "CDP_ENDPOINTS", frozenset({"http://registered:9222"})),
            patch.object(config, "EXECUTOR_TOKEN", "executor-token"),
            patch.object(config, "ADMIN_TOKEN", "admin-token"),
            patch.object(config, "INTENT_TOKEN", "intent-token"),
            patch.object(config, "APPROVER_TOKEN", "approver-token"),
            patch.object(gs, "signer", self.signer),
            patch.object(gs, "log", CertificateLog(self.root / "audit.jsonl")),
            patch.object(gs, "capability_registry", CapabilityRegistry(self.signer)),
            patch.object(gs.registry, "snapshot", return_value={}),
            patch.object(gs, "analyze_command_danger", return_value={"dangerous": True}),
            patch.object(gs, "anchor_intent", return_value={"rules": []}),
            patch.object(gs, "anchor_effect_llm", return_value=None)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        for name in ("SESSION_POLICIES", "SESSION_EPOCHS", "SESSION_EFFECTS", "SESSION_TAINT",
                     "SESSION_CONFIRM_BUDGET", "PENDING_CONFIRMS", "APPROVAL_TICKETS", "EXECUTION_TICKETS"):
            getattr(gs, name).clear()
        gs._reset_session_policy("s", {"intent_text": "read one file", "rules": [rule("read_file", self.path)]})
        self.caps = {"actions": ["read_file"], "filesystem_read": [str(self.allowed) + "/*"]}
        self.cert = self.register(self.caps)

    def register(self, caps, tool="tool", implementation="v1"):
        return gs.register_tool(ToolRegistrationRequest(tool_id=tool,
            declared_capabilities=caps, implementation_hash=implementation)).capability_cert_id

    def request(self, path=None, action="read_file", payload=None, cert=None, tool="tool"):
        return AuthorizeRequest(session_id="s", intent_anchor={"text": "untrusted client text"},
            tool={"tool_id": tool, "capability_cert_id": cert or self.cert},
            action={"type": action, "target": path or self.path, "payload": payload or {}}, visual_state={})

    def consume_request(self, req, result):
        return ConsumeRequest(ticket=result.execution_ticket, session_id=req.session_id,
                              tool=req.tool, action=req.action)

    def approve(self, req):
        result = gs.authorize(req)
        self.assertEqual(result.verdict, "CONFIRM")
        approved = gs.confirm(ConfirmRequest(token=result.confirm_token, approve=True))
        return req.model_copy(update={"approval_ticket": approved["ticket"]})

    def test_parameter_constraints_are_hard_even_with_approval(self):
        caps = dict(self.caps, parameter_constraints={"units": {"type": "integer", "maximum": 10}})
        cert = self.register(caps)
        req = self.request(cert=cert, payload={"units": 11})
        for approved in (False, True):
            result = gs._authorize(req, approved=approved)
            self.assertEqual(result.verdict, "BLOCK")
            self.assertEqual(result.decision_rule, "capability.parameters")
            self.assertIsNone(result.confirm_token)
            self.assertIsNone(result.execution_ticket)
        missing = gs.authorize(self.request(cert=cert))
        self.assertEqual(missing.decision_rule, "capability.parameters")

    def test_parameter_constraint_registration_http_rejects_unsupported(self):
        body = {"tool_id": "bad-schema", "declared_capabilities": dict(self.caps,
            parameter_constraints={"units": {"maximum": "10"}})}
        status, _ = asyncio.run(http_call("/register_tool", body, token="admin-token"))
        self.assertEqual(status, 422)

    def test_parameter_checks_repeat_at_consume_and_bind_approval(self):
        from policy.parameter_constraints import check_constraints
        cert = self.register(dict(self.caps, parameter_constraints={"units": {"maximum": 10}}))
        req = self.request(cert=cert, payload={"units": 10})
        with patch("policy.engine.check_constraints", wraps=check_constraints) as checked:
            result = gs.authorize(req)
            self.assertEqual(result.verdict, "ALLOW")
            gs.consume(self.consume_request(req, result))
            self.assertEqual(checked.call_count, 2)
        gs.SESSION_POLICIES["s"]["rules"] = [rule("read_file", self.other)]
        approved = self.approve(req)
        changed = approved.model_copy(deep=True)
        changed.action.payload["units"] = 11
        with self.assertRaises(HTTPException):
            gs.authorize(changed)

    def test_nested_taint_hard_block_cannot_be_approved(self):
        cert = self.register({"actions": ["send"], "network_egress": "allowed"}, "send")
        gs.SESSION_POLICIES["s"]["rules"] = [rule("send", "recipient")]
        gs.SESSION_TAINT["s"] = {"dirty": True, "tainted_objects": [{"object_id": "sensitive-object", "source": "private_file"}]}
        req = self.request("recipient", action="send", tool="send", cert=cert,
                           payload={"attachments": [{"file": "sensitive-object"}]})
        for approved in (False, True):
            result = gs._authorize(req, approved=approved)
            self.assertEqual((result.verdict, result.decision_rule), ("BLOCK", "p5.taint"))
            self.assertIsNone(result.execution_ticket)

    def test_business_policy_survives_reanchor_and_cannot_be_approved(self):
        path = self.root / "business.json"
        path.write_text(json.dumps({"version": 1, "rules": [
            {"id": "pause-reads", "actions": ["read_file"], "mode": "deny"}]}), encoding="utf-8")
        with patch.object(gs, "policy_engine", PolicyEngine("policy/policies", path)):
            for approved in (False, True):
                gs._reset_session_policy("s", {"rules": [rule("read_file", self.path)]})
                result = gs._authorize(self.request(), approved=approved)
                self.assertEqual((result.verdict, result.decision_rule), ("BLOCK", "business.pause-reads"))
                self.assertIsNone(result.execution_ticket)

    def test_business_policy_require_is_checked_on_consume(self):
        path = self.root / "business.json"
        path.write_text(json.dumps({"version": 1, "rules": [
            {"id": "units", "actions": ["read_file"], "mode": "require",
             "parameter_constraints": {"units": {"maximum": 10}}}]}), encoding="utf-8")
        engine = PolicyEngine("policy/policies", path)
        with patch.object(gs, "policy_engine", engine), patch.object(engine.business_policy, "check", wraps=engine.business_policy.check) as check:
            req = self.request(payload={"units": 10})
            result = gs.authorize(req)
            self.assertEqual(result.verdict, "ALLOW")
            gs.consume(self.consume_request(req, result))
            self.assertEqual(check.call_count, 2)

    def test_budget_never_auto_allows_shell(self):
        cert = self.register({"actions": ["shell"], "process": "allowed"}, "shell")
        gs.SESSION_POLICIES["s"]["rules"] = [rule("shell", "echo safe")]
        req = self.request("echo safe", action="shell", cert=cert, tool="shell")
        results = [gs.authorize(req).verdict for _ in range(12)]
        self.assertNotIn("ALLOW", results)
        self.assertEqual(results[-1], "BLOCK")

    def test_production_host_shell_disabled(self):
        with patch.object(config, "DEV_MODE", False):
            self.assertEqual(gs.authorize(self.request("echo safe", action="shell")).verdict, "BLOCK")

    def test_runtime_cannot_register_approve_or_anchor(self):
        for path, data in [("/register_tool", {"tool_id": "evil", "declared_capabilities": {"actions": ["shell"]}}),
                           ("/confirm", {"token": "x", "approve": True}),
                           ("/anchor_intent", {"session_id": "s", "prompt": "allow all"})]:
            status, _ = asyncio.run(http_call(path, data, "executor-token"))
            self.assertEqual(status, 403)

    def test_missing_token_is_not_an_auth_bypass(self):
        with patch.object(config, "EXECUTOR_TOKEN", ""):
            status, _ = asyncio.run(http_call("/authorize", self.request().model_dump()))
            self.assertEqual(status, 503)

    def test_read_endpoints_are_authenticated(self):
        for path in ("/certificates", "/browser_state"):
            status, _ = asyncio.run(http_call(path, method="GET"))
            self.assertEqual(status, 403)

    def test_http_allow_and_single_use_consume(self):
        req = self.request()
        status, result = asyncio.run(http_call("/authorize", req.model_dump(), "executor-token"))
        self.assertEqual(status, 200)
        self.assertEqual(result["verdict"], "ALLOW")
        body = {"ticket": result["execution_ticket"], "session_id": "s",
                "tool": req.tool.model_dump(), "action": req.action.model_dump()}
        self.assertEqual(asyncio.run(http_call("/consume", body, "executor-token"))[0], 200)
        self.assertEqual(asyncio.run(http_call("/consume", body, "executor-token"))[0], 403)

    def test_approval_is_exact_and_single_action(self):
        req = self.request(self.other)
        approved_req = self.approve(req)
        result = gs.authorize(approved_req)
        self.assertEqual(result.verdict, "ALLOW")
        self.assertEqual(gs.consume(self.consume_request(req, result))["status"], "consumed")
        self.assertEqual(gs.authorize(req).verdict, "CONFIRM")
        with self.assertRaises(HTTPException):
            gs.authorize(approved_req)

    def test_approval_cannot_change_payload(self):
        req = self.approve(self.request(self.other))
        req.action.payload["content"] = "different"
        with self.assertRaises(HTTPException):
            gs.authorize(req)

    def test_hard_path_failure_never_becomes_confirmation(self):
        self.assertEqual(gs.authorize(self.request(str(self.root / "outside"))).verdict, "BLOCK")

    def test_path_traversal(self):
        escaped = str(self.allowed / ".." / "outside")
        self.assertFalse(within_envelope(escaped, self.caps["filesystem_read"]))
        gs.SESSION_POLICIES["s"]["rules"] = [rule("read_file", escaped)]
        self.assertEqual(gs.authorize(self.request(escaped)).verdict, "BLOCK")

    def test_empty_and_relative_paths_denied(self):
        self.assertFalse(within_envelope(self.path, []))
        self.assertFalse(within_envelope("relative.txt", [str(self.allowed) + "/*"]))

    def test_alias_target_conflict_denied(self):
        self.assertEqual(gs.authorize(self.request(payload={"path": self.other})).verdict, "BLOCK")

    def test_changed_epoch_revokes_approval_and_execution(self):
        result = gs.authorize(self.request())
        approved_req = self.approve(self.request(self.other))
        gs._reset_session_policy("s", {"rules": [rule("read_file", self.path)]})
        with self.assertRaises(HTTPException):
            gs.consume(self.consume_request(self.request(), result))
        with self.assertRaises(HTTPException):
            gs.authorize(approved_req)

    def test_changed_capability_revokes_execution(self):
        result = gs.authorize(self.request())
        self.register(self.caps, implementation="v2")
        with self.assertRaises(HTTPException):
            gs.consume(self.consume_request(self.request(), result))

    def test_expired_execution_denied(self):
        req = self.request()
        result = gs.authorize(req)
        gs.EXECUTION_TICKETS[result.execution_ticket]["expires_at"] = 0
        with self.assertRaises(HTTPException):
            gs.consume(self.consume_request(req, result))

    def test_concurrent_consumption_at_most_once(self):
        req = self.request()
        result = gs.authorize(req)
        def consume():
            try:
                gs.consume(self.consume_request(req, result))
                return True
            except HTTPException:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(lambda _: consume(), range(2))), 1)

    def test_client_cannot_seed_session_with_signed_profile(self):
        req = self.request().model_copy(update={"session_id": "unanchored"})
        with self.assertRaises(HTTPException):
            gs.authorize(req)

    def test_cross_turn_feedback_not_preserved(self):
        gs.SESSION_POLICIES["s"]["rules"][0]["reason"] = "feedback loop: approved"
        gs._reset_session_policy("s", {"rules": []})
        self.assertEqual(gs.SESSION_POLICIES["s"]["rules"], [])

    def test_capability_schema_preserves_effect_and_migrates_legacy(self):
        caps = CapabilityDeclaration(actions=["email"], network="allowed",
                    effect_type="external_communication", target_type="recipient").model_dump()
        self.assertEqual(caps["effect_type"], "external_communication")
        self.assertTrue(taint.is_sink(caps))
        with self.assertRaises(ValueError):
            CapabilityDeclaration(effect_typo="mail")

    def test_online_behavior_alignment_blocks_recipient(self):
        cert = self.register({"actions": ["email"], "external_share": "allowed",
            "effect_type": "external_communication", "target_type": "recipient",
            "sensitive_params": ["to"]}, "email")
        gs.SESSION_POLICIES["s"]["rules"] = [rule("email", "outside@example.invalid", "payload.to")]
        gs.SESSION_EFFECTS["s"] = {"allowed_recipients": ["allowed@example.invalid"]}
        result = gs.authorize(self.request("send", action="email", cert=cert, tool="email",
                                           payload={"to": "outside@example.invalid"}))
        self.assertEqual(result.verdict, "BLOCK")
        self.assertEqual(result.decision_rule, "behavior_alignment")

    def test_or_true_does_not_constrain_recipient(self):
        pred = {"op": "or", "args": [{"op": "eq", "field": "payload.to", "value": "allowed"}, {"op": "true"}]}
        engine = PolicyEngine("policy/policies")
        result = engine.evaluate(Action(type="email", target="send", payload={"to": "outside"}), "unknown", 0,
            capability={"actions": ["email"], "external_share": "allowed", "sensitive_params": ["to"]},
            rules=[{"tool": "email", "decision": "allow", "predicate": pred}])
        self.assertEqual(result["verdict"], "CONFIRM")

    def test_exact_command_semantics(self):
        self.assertFalse(symbolic.predicate_holds({"op": "eq", "field": "target", "value": "echo A"}, {"target": "echo a"}))
        self.assertFalse(symbolic.predicate_holds({"op": "eq", "field": "target", "value": "/a/b"}, {"target": "/a%2fb"}))

    def test_certificate_envelope_tampering_denied(self):
        req = self.request()
        result = gs.authorize(req)
        cert = result.certificates[0].model_dump()
        cert["trust"] = "trusted"
        ok, _, _ = PolicyEngine._verify_certificate(cert, req.action, gs._verify_evidence_certificate)
        self.assertFalse(ok)

    def test_certificate_payload_tampering_denied(self):
        req = self.request()
        cert = gs.authorize(req).certificates[0].model_dump()
        cert["payload"]["action_target"] = "changed"
        self.assertFalse(PolicyEngine._verify_certificate(cert, req.action, gs._verify_evidence_certificate)[0])

    def test_unsigned_visual_evidence_cannot_allow(self):
        engine = PolicyEngine("policy/policies")
        result = engine.evaluate(Action(type="click", target="Submit"), "trusted", 1,
            capability={"actions": ["click"]}, rules=[rule("click", "Submit")])
        self.assertEqual(result["verdict"], "BLOCK")

    def test_attached_ignores_forged_snapshot(self):
        with patch("browser.capture.capture_attached", return_value=(None, [{"name": "REAL"}])):
            ctx = gs.context_from_visual_state({"mode": "attached", "cdp_endpoint": "http://registered:9222",
                                                "a11y_snapshot": [{"name": "FORGED"}]})
        self.assertEqual(ctx.a11y_snapshot, [{"name": "REAL"}])

    def test_unregistered_cdp_denied(self):
        with self.assertRaises(HTTPException):
            gs.context_from_visual_state({"mode": "attached", "cdp_endpoint": "http://untrusted:9222"})

    def test_confirmed_read_is_tainted_at_consumption(self):
        self.cert = self.register({**self.caps, "sources": ["private_file"]}, implementation="source")
        req = self.request(self.other)
        result = gs.authorize(self.approve(req))
        gs.consume(self.consume_request(req, result))
        self.assertTrue(gs.SESSION_TAINT["s"]["dirty"])
        self.assertEqual(gs.SESSION_TAINT["s"]["tainted_objects"][0]["object_id"], self.other)

    def test_log_failure_never_issues_execution_ticket(self):
        with patch.object(gs.log, "append", side_effect=OSError("unavailable")):
            with self.assertRaises(OSError):
                gs.authorize(self.request())
        self.assertEqual(gs.EXECUTION_TICKETS, {})

    def test_sdk_unknown_verdict_never_calls_tool(self):
        calls = []
        client = ICBGuardClient(token="executor")
        with patch.object(client, "authorize", return_value=AuthorizeResult("INVALID", "bad")):
            wrapped = guard(client, "tool", "read_file")(lambda target: calls.append(target))
            with self.assertRaises(AuthorizationBlocked):
                wrapped(self.path)
        self.assertEqual(calls, [])

    def test_sdk_binds_full_arguments_and_requires_consumption(self):
        calls, seen = [], []
        client = ICBGuardClient(token="executor")
        def authorize(*args, **kwargs):
            seen.append(kwargs["payload"])
            return AuthorizeResult("ALLOW", "ok")
        with patch.object(client, "authorize", side_effect=authorize):
            wrapped = guard(client, "tool", "write_file")(lambda target, content: calls.append(content))
            with self.assertRaises(AuthorizationBlocked):
                wrapped(self.path, "secret")
        self.assertEqual(seen[0]["content"], "secret")
        self.assertEqual(calls, [])

    def test_http_rejects_policy_path_traversal(self):
        req = self.request().model_dump()
        req["action"]["type"] = "../../outside"
        self.assertEqual(asyncio.run(http_call("/authorize", req, "executor-token"))[0], 422)

    def test_new_taint_revokes_pending_approval(self):
        approved = self.approve(self.request(self.other))
        gs.SESSION_TAINT["s"] = {"dirty": True, "tainted_objects": []}
        with self.assertRaises(HTTPException):
            gs.authorize(approved)

    def test_audit_rejects_recomputed_unsigned_chain(self):
        audit = CertificateLog(self.root / "signed.jsonl", signer=self.signer)
        audit.append({"id": "one", "verdict": "BLOCK"})
        entry = json.loads(audit.path.read_text())
        entry["verdict"] = "ALLOW"
        from attestation.hashing import object_hash
        entry["hash"] = object_hash({k: v for k, v in entry.items() if k not in ("hash", "log_signature")})
        audit.path.write_text(json.dumps(entry) + "\n")
        self.assertFalse(audit.verify_chain()["ok"])
        with self.assertRaises(RuntimeError):
            audit.append({"id": "two"})

    def test_malformed_llm_proposal_is_not_partially_allowed(self):
        from policy.intent_anchor import _sanitize_rules, _sanitize_predicate, analyze_command_danger
        self.assertIsNone(_sanitize_predicate({"op": "and", "args": [{"op": "true"}, {"op": "invalid"}]}))
        self.assertEqual(_sanitize_rules([rule("read_file", self.path), {"decision": "deny", "predicate": {"op": "invalid"}}]), [])
        with patch("policy.intent_anchor.intent_llm_configured", return_value=True), patch("policy.intent_anchor._chat", return_value="{}"):
            self.assertIsNone(analyze_command_danger("test-invalid-json-result"))

    def test_real_file_effect_requires_valid_execution_ticket(self):
        client = ICBGuardClient(token="executor")
        self.cert = self.register({"actions": ["write_file"], "filesystem_write": [str(self.allowed) + "/*"]})
        gs.SESSION_POLICIES["s"]["rules"] = [{"tool": "write_file", "decision": "allow", "predicate": {
            "op": "and", "args": [{"op": "eq", "field": "target", "value": self.path},
                                  {"op": "eq", "field": "payload.content", "value": "approved text"}]}}]
        def authorize(tool, action_type, target, intent, **kwargs):
            req = self.request(target, action=action_type, payload=kwargs["payload"])
            response = gs.authorize(req)
            return AuthorizeResult(**response.model_dump(), request=req.model_dump())
        def consume(result):
            req = AuthorizeRequest(**result.request)
            return gs.consume(self.consume_request(req, result))
        def write_file(target, content):
            Path(target).write_text(content)
        with patch.object(client, "authorize", side_effect=authorize), patch.object(client, "consume", side_effect=consume):
            wrapped = guard(client, "tool", "write_file")(write_file)
            wrapped(self.path, "approved text")
            self.assertEqual(Path(self.path).read_text(), "approved text")
            outside = self.root / "unauthorized.txt"
            with self.assertRaises(AuthorizationBlocked):
                wrapped(str(outside), "approved text")
            self.assertFalse(outside.exists())

    def test_production_rejects_missing_or_shared_credentials(self):
        with patch.object(config, "DEV_MODE", False):
            with self.assertRaises(RuntimeError):
                config.validate_security_config()

    def test_default_and_keyword_arguments_are_authorized(self):
        client = ICBGuardClient(token="executor")
        observed = []
        def authorize(*args, **kwargs):
            observed.append(kwargs["payload"])
            return AuthorizeResult("BLOCK", "test")
        def send(target, body="default body", **kwargs):
            self.fail("Blocked function executed")
        with patch.object(client, "authorize", side_effect=authorize):
            with self.assertRaises(AuthorizationBlocked):
                guard(client, "send", "send")(send)("recipient", to="other")
        self.assertEqual(observed[0]["body"], "default body")
        self.assertEqual(observed[0]["to"], "other")

    def test_replay_metrics_do_not_claim_attack_success(self):
        import io
        from contextlib import redirect_stdout
        from demo.attacks.replay_rjudge_symbolic import report
        def record(index, label, verdict):
            return {"id": index, "label": label, "attack_type": "injection", "actions": [
                {"tool": "read_file", "verdict": verdict, "latency_ms": 1, "target": "x"}]}
        with redirect_stdout(io.StringIO()):
            metrics = report([record(1, 1, "ALLOW"), record(2, 0, "CONFIRM"), record(3, 1, "ERROR")], "test")
        self.assertIsNone(metrics["attack_success_rate"])
        self.assertFalse(metrics["executed"])
        self.assertEqual(metrics["errors"], 1)
        self.assertEqual(metrics["record_level"]["intervention_rate_safe"], 1)


if __name__ == "__main__":
    unittest.main()
