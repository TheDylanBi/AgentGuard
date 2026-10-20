"""Run in the agentdojo environment. All model responses are local fixtures."""
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from adapters.agentdojo_pi.host import SimulationHost, load_manifest
from adapters.agentdojo_pi.pipeline import PiPipeline
from attestation.signer import Signer
from attestation.log import CertificateLog

MANIFEST = Path(__file__).resolve().parents[1] / "adapters/agentdojo_pi/workspace_manifest.json"
PI = Path("D:/Pi/pi-node/current/node_modules/@earendil-works/pi-coding-agent")
NODE = "D:/Pi/pi-node/current/node.exe"


class FixtureMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.suite = get_suite("v1.2.2", "workspace")
        self.runtime = FunctionsRuntime(self.suite.tools)
        self.env = self.suite.load_and_inject_default_environment({})
        self.manifest = load_manifest(MANIFEST, self.runtime)

    def host(self, mode="guarded", **kwargs):
        signer = Signer(self.root / "private", self.root / "public")
        audit = CertificateLog(self.root / "audit.jsonl", signer=signer)
        return SimulationHost(self.runtime, self.env, self.manifest, signer, audit, mode=mode, **kwargs)


class HostTests(FixtureMixin, unittest.TestCase):
    def test_manifest_exact_coverage(self):
        data = copy.deepcopy(self.manifest)
        del data["tools"]["send_email"]
        path = self.root / "bad.json"
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            load_manifest(path, self.runtime)

    def test_baseline_executes_official_runtime(self):
        host = self.host("baseline")
        before = self.env.model_dump()
        _, error = host.call("1", "create_file", {"filename": "fixture.txt", "content": "fixture"})
        self.assertIsNone(error)
        self.assertNotEqual(before, self.env.model_dump())
        self.assertEqual(host.counts["executed"], 1)

    def test_sensitive_without_intent_is_blocked(self):
        host = self.host()
        before = self.env.model_dump()
        _, error = host.call("1", "create_file", {"filename": "fixture.txt", "content": "fixture"})
        self.assertIn("ICB-BLOCK", error)
        self.assertEqual(before, self.env.model_dump())

        self.assertEqual(host.counts["executed"], 0)

    def test_schema_repair_does_not_create_authority(self):
        host = self.host()
        before = self.env.model_dump()
        host.call("bad", "create_file", {"filename": "fixture", "content": "x", "extra": True})
        self.assertTrue(host.last_feedback["retryable"])
        host.call("fixed", "create_file", {"filename": "fixture", "content": "x"})
        self.assertFalse(host.last_feedback["retryable"])
        self.assertEqual(host.counts["executed"], 0)
        self.assertEqual(before, self.env.model_dump())

    def test_stopped_host_cannot_execute_other_allowed_tool(self):
        host = self.host(rules=[{"tool": "get_current_day", "decision": "allow", "predicate": {"op": "true"}},
                                {"tool": "create_file", "decision": "deny", "predicate": {"op": "true"}}])
        host.call("bad", "create_file", {"filename": "fixture", "content": "x"})
        self.assertTrue(host.last_feedback["stop_task"])
        self.assertIsNotNone(host.call("other", "get_current_day", {})[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_confirm_is_not_auto_approved(self):
        host = self.host(rules=[{"tool": "get_current_day", "decision": "allow", "predicate": {
            "op": "eq", "field": "target", "value": "another-target"}}])
        _, error = host.call("1", "get_current_day", {})
        self.assertIn("ICB-CONFIRM", error)
        self.assertEqual(host.counts["executed"], 0)

    def test_explicit_read_rule_uses_real_policy(self):
        host = self.host(rules=[{"tool": "get_current_day", "decision": "allow", "predicate": {"op": "true"}}])
        _, error = host.call("1", "get_current_day", {})
        self.assertIsNone(error)
        self.assertEqual(host.counts["ALLOW"], 1)

    def test_denial_replay_unknown_tool_unknown_arguments(self):
        host = self.host("baseline")
        self.assertIn("ICB-BLOCK", host.call("1", "bash", {"command": "bad"})[1])
        self.assertIn("ICB-BLOCK", host.call("2", "get_current_day", {"approved": True})[1])
        with self.assertRaises(ValueError):
            host.call("2", "get_current_day", {})
        self.assertEqual(host.counts["executed"], 0)

    def test_failed_start_audit_prevents_effect(self):
        host = self.host("baseline")
        before = self.env.model_dump()
        with patch.object(host.audit, "append", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                host.call("1", "create_file", {"filename": "fixture", "content": "fixture"})
        self.assertEqual(before, self.env.model_dump())

    def test_business_deny_cannot_be_overridden_by_intent(self):
        path = self.root / "business.json"
        path.write_text(json.dumps({"version": 1, "rules": [{"id": "stop", "actions": ["get_current_day"], "mode": "deny"}]}))
        host = self.host(business_policy=path, rules=[{
            "tool": "get_current_day", "decision": "allow", "predicate": {"op": "true"}}])
        self.assertIn("ICB-BLOCK", host.call("1", "get_current_day", {})[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_hard_parameter_constraints_survive_bridge(self):
        self.manifest["tools"]["create_file"]["capability"]["parameter_constraints"] = {
            "filename": {"enum": ["permitted.txt"]}}
        host = self.host(rules=[{"tool": "create_file", "decision": "allow", "predicate": {"op": "true"}}])
        before = self.env.model_dump()
        self.assertIn("ICB-BLOCK", host.call("1", "create_file", {"filename": "other.txt", "content": "x"})[1])
        self.assertEqual(before, self.env.model_dump())

    def test_sources_are_recorded_and_sessions_are_separate(self):
        host = self.host(rules=[{"tool": "list_files", "decision": "allow", "predicate": {"op": "true"}}])
        self.assertIsNone(host.call("1", "list_files", {})[1])
        self.assertTrue(host.taint["dirty"])
        self.assertFalse(self.host().taint["dirty"])

    def test_nested_taint_reference_blocks_mutation(self):
        host = self.host(rules=[{"tool": "send_email", "decision": "allow", "predicate": {"op": "true"}}])
        host.taint = {"dirty": True, "tainted_objects": [{"object_id": "private-object", "source": "external_untrusted"}]}
        before = self.env.model_dump()
        _, error = host.call("1", "send_email", {"recipients": ["fixture@example.com"], "subject": "fixture",
            "body": "fixture", "attachments": [{"type": "file", "file_id": "private-object"}]})
        self.assertIn("ICB-BLOCK", error)
        self.assertEqual(before, self.env.model_dump())
        self.assertEqual(host.audit.get("1:denied")["rule"], "p5.taint")


class PiSmokeTests(FixtureMixin, unittest.TestCase):
    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_boundary_compiler_runs_through_real_pi_and_preserves_snapshot(self):
        boundary = {"version": 1, "grants": [{"tool": "get_current_day", "purpose": "Read the reference date",
                                               "parameters": {}}], "denies": []}
        pipeline, _, _, _ = self.smoke("guarded", tool="get_current_day", intent_format="boundary", boundary=boundary)
        self.assertEqual(pipeline.runs[0]["counts"]["executed"], 1)
        snapshot = json.loads(next((self.root / "out").glob("policy-*.json")).read_text())
        self.assertEqual(snapshot["authorization_boundary"], boundary)
        self.assertEqual(snapshot["boundary_report"]["unresolved"], [])

    """Real installed pi SDK, real AgentDojo tools; no remote API/credentials."""
    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_null_calendar_strings_do_not_crash_or_execute_coerced_values(self):
        pipe, before, messages, _ = self.smoke("baseline", tool="create_calendar_event", args={
            "title": "Fixture", "start_time": "2024-05-30 10:20", "end_time": "2024-05-30 11:20",
            "description": None, "location": None, "participants": ["fixture@example.com"]})
        self.assertEqual(before, self.env.model_dump())
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 0)
        self.assertIsNone(messages[1]["tool_calls"][0].args["description"])
        self.assertIn("Invalid tool arguments", messages[2]["error"])

    def smoke(self, mode, tool="create_file", args=None, rules=None, official=False, broken=False,
              sequence=None, stopped=False, batch=False, max_turns=16, echo_result=False,
              expected_utility=None, steps=None, final_violation=False,
              finish_reason=None, reasoning=False, thinking_format=None, response_text=None,
              context_window=32000, response_usage=None, action_output_budget="sdk",
              final_finish_reason=None, intent_format="rules", boundary=None):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append(body)
                if broken:
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":{"message":"fixture denied","type":"authentication_error"}}')
                    return
                has_result = any(m["role"] == "tool" for m in body["messages"])
                turn = sum(m["role"] == "tool" for m in body["messages"])
                delta = {"role": "assistant", "content": "Completed fixture."} if has_result else {
                    "role": "assistant", "tool_calls": [{"index": 0, "id": "fixture_call", "type": "function",
                        "function": {"name": tool, "arguments": json.dumps(args or {})}}]}
                if sequence and turn < len(sequence):
                    has_result = False
                    delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": f"fixture_{turn}",
                        "type": "function", "function": {"name": tool, "arguments": json.dumps(sequence[turn])}}]}
                if steps and turn < len(steps):
                    has_result = False
                    step = steps[turn]
                    delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": f"step_{turn}",
                        "type": "function", "function": {"name": step["tool"], "arguments": json.dumps(step["arguments"])}}]}
                if final_violation and has_result:
                    has_result = False
                    delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "forbidden_final_call",
                        "type": "function", "function": {"name": "get_current_day", "arguments": "{}"}}]}
                if batch and "tool_calls" in delta:
                    second = copy.deepcopy(delta["tool_calls"][0])
                    second.update(index=1, id="pending_call")
                    delta["tool_calls"].append(second)
                if has_result and echo_result:
                    # Fixture answer derives only from the tool response, never
                    # from task ground truth or environment internals.
                    ordering = body["messages"] if echo_result == "first" else reversed(body["messages"])
                    delta["content"] = str(next(m["content"] for m in ordering if m["role"] == "tool"))
                if response_text is not None:
                    delta = {"role": "assistant", "content": response_text}
                    has_result = True
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for item in (
                    {"id": "fixture", "object": "chat.completion.chunk", "created": 1, "model": "fixture",
                     "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                    {"id": "fixture", "object": "chat.completion.chunk", "created": 1, "model": "fixture",
                     "choices": [{"index": 0, "delta": {}, "finish_reason": None if has_result and final_finish_reason == "missing" else (final_finish_reason if has_result and final_finish_reason else finish_reason) or ("stop" if has_result else "tool_calls")}],
                     **({"usage": response_usage} if response_usage else {})}):
                    self.wfile.write(("data: " + json.dumps(item) + "\n\n").encode())
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        config = self.root / "pi"
        config.mkdir()
        (config / "auth.json").write_text("{}")
        (config / "models.json").write_text(json.dumps({"providers": {"fixture": {
            "baseUrl": f"http://127.0.0.1:{server.server_port}/v1", "api": "openai-completions",
            "apiKey": "local-fixture-only", "models": [{"id": "fixture", "name": "Fixture",
                "reasoning": reasoning, "input": ["text"], "contextWindow": context_window, "maxTokens": 1024,
                **({"compat": {"thinkingFormat": thinking_format}} if thinking_format else {}),
                "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0}}]}}}))
        pipeline = PiPipeline(manifest=MANIFEST, pi_package=PI, pi_agent_dir=config,
            provider="fixture", model="fixture", mode=mode, output=self.root / "out", node=NODE, timeout=45,
            max_turns=max_turns, trusted_current_day=self.env.calendar.current_day.isoformat(),
            action_output_budget=action_output_budget, intent_format=intent_format)
        before = self.env.model_dump()
        with patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
             patch("policy.intent_anchor.intent_llm_configured", return_value=True), \
             patch("adapters.agentdojo_pi.pipeline.anchor_rules_llm", return_value=rules or []), \
             patch("policy.intent_anchor.anchor_boundary_llm", return_value=boundary), \
             patch("adapters.agentdojo_pi.pipeline.anchor_effect_llm", return_value={}):
            if broken:
                with self.assertRaises(RuntimeError):
                    pipeline.query("Run the fixture tool.", self.runtime, self.env)
                self.assertEqual(pipeline.runs[0]["status"], "error")
                self.assertEqual(pipeline.runs[0]["counts"]["executed"], 0)
                return
            if official == "cli":
                from adapters.agentdojo_pi.run import main
                output = self.root / "cli-output"
                status = main(["--mode", mode, "--provider", "fixture", "--model", "fixture",
                    "--pi-package", str(PI), "--pi-agent-dir", str(config), "--node", NODE,
                    "--user-task", "user_task_0", "--output", str(output), "--max-turns", str(max_turns)])
                self.assertEqual(status, 0)
                summary = json.loads((output / "summary.json").read_text())
                self.assertEqual(summary["status"], "completed_with_stops" if stopped else "completed")
                self.assertIsNone(summary["metrics"]["attack_success_rate"])
                self.assertEqual(summary["metrics"]["utility_results"]["count"], 1)
                self.assertTrue(summary["agentdojo_revision"])
                pipeline.runs = summary["runs"]
                messages = None
            elif official:
                from agentdojo.benchmark import benchmark_suite_without_injections, benchmark_suite_with_injections
                from agentdojo.logging import OutputLogger
                with OutputLogger(str(self.root / "official")):
                    common = dict(logdir=self.root / "official", force_rerun=True,
                                  user_tasks=["user_task_0"], benchmark_version="v1.2.2")
                    if official == "attack":
                        from agentdojo.attacks import load_attack
                        result = benchmark_suite_with_injections(pipeline, self.suite,
                            load_attack("tool_knowledge", self.suite, pipeline),
                            injection_tasks=["injection_task_0"], **common)
                        self.assertEqual(len(result["security_results"]), 1)
                    else:
                        result = benchmark_suite_without_injections(pipeline, self.suite, **common)
                self.assertEqual(len(result["utility_results"]), 1)
                if expected_utility is not None:
                    self.assertEqual(list(result["utility_results"].values()), [expected_utility])
                messages = None
            else:
                _, _, _, messages, _ = pipeline.query("Run the fixture tool.", self.runtime, self.env)
        self.assertEqual(pipeline.runs[-1]["status"], "stopped" if final_violation else "answered_after_stop" if stopped else "completed")
        count = len(steps or sequence) + 1 if (steps or sequence) else 2
        self.assertEqual(len(requests), count * (2 if official == "attack" else 1))
        self.assertEqual({t["function"]["name"] for t in requests[0]["tools"]}, set(self.runtime.functions))
        self.assertEqual("Task policy has candidate allow rules" in str(requests[0]["messages"]), mode == "guarded")
        if messages:
            self.assertEqual(messages[1]["tool_calls"][0].function, tool)
        return pipeline, before, messages, requests

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_real_sdk_baseline_mutates_simulated_environment(self):
        pipe, before, _, _ = self.smoke("baseline", args={"filename": "fixture.txt", "content": "a\u2028b"})
        self.assertNotEqual(before, self.env.model_dump())
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 1)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_real_sdk_guard_blocks_mutation_retains_proposal(self):
        pipe, before, messages, requests = self.smoke("guarded", args={"filename": "fixture.txt", "content": "fixture"}, stopped=True)
        self.assertEqual(before, self.env.model_dump())
        self.assertEqual(pipe.runs[0]["counts"]["BLOCK"], 1)
        self.assertIn("ICB-BLOCK", messages[2]["error"])
        self.assertEqual(len(requests), 2)
        self.assertFalse(requests[-1].get("tools"))
        self.assertTrue(pipe.runs[0]["final_answer_received"])

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_repair_feedback_reaches_model_and_revised_call_is_checked(self):
        pipe, _, messages, requests = self.smoke("guarded", tool="get_current_day",
            rules=[{"tool": "get_current_day", "decision": "allow", "predicate": {"op": "true"}}],
            sequence=[{"unexpected": True}, {}])
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 1)
        self.assertIn("safety_feedback", str(requests[1]["messages"]))
        self.assertEqual(len([m for m in messages if m["role"] == "tool"]), 2)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_identical_rejection_stops_without_third_request(self):
        pipe, before, _, _ = self.smoke("guarded", tool="get_current_day",
            sequence=[{"unexpected": True}, {"unexpected": True}], stopped=True)
        self.assertEqual(pipe.runs[0]["stop_reason"], "repeated_rejected_call")
        self.assertEqual(before, self.env.model_dump())

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_changed_invalid_arguments_have_bounded_retries(self):
        pipe, _, _, _ = self.smoke("guarded", tool="get_current_day",
            sequence=[{"unexpected": 1}, {"unexpected": 2}, {"unexpected": 3}], stopped=True)
        self.assertEqual(pipe.runs[0]["stop_reason"], "repair_budget_exhausted")
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 0)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_stopped_prescreen_does_not_abort_official_attack_loop(self):
        pipe, _, _, _ = self.smoke("guarded", args={"filename": "fixture", "content": "fixture"},
                                  official="attack", stopped=True)
        self.assertEqual(len(pipe.runs), 2)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_stop_cancels_pending_parallel_proposals(self):
        pipe, before, messages, _ = self.smoke("guarded", args={"filename": "fixture", "content": "x"},
                                              stopped=True, batch=True)
        self.assertEqual(len(messages[1]["tool_calls"]), 2)
        self.assertEqual(messages[3]["error"], "controller_stopped")
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 0)
        self.assertEqual(before, self.env.model_dump())

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_cli_reports_controlled_stop_separately(self):
        self.smoke("guarded", args={"filename": "fixture", "content": "fixture"}, official="cli", stopped=True)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_turn_limit_stops_before_extra_model_request(self):
        pipe, _, messages, requests = self.smoke("guarded", tool="get_current_day",
            rules=[{"tool": "get_current_day", "decision": "allow", "predicate": {"op": "true"}}],
            sequence=[{}, {}], max_turns=2, stopped=True)
        self.assertEqual(pipe.runs[0]["stop_reason"], "turn_limit_exceeded")
        self.assertEqual(pipe.runs[0]["turns"], 3)
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 2)
        self.assertEqual(len(requests), 3)
        self.assertFalse(requests[-1].get("tools"))

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_final_answer_at_turn_limit_is_completed(self):
        pipe, _, _, _ = self.smoke("baseline", tool="get_current_day", max_turns=2)
        self.assertEqual(pipe.runs[0]["turns"], 2)
        self.assertNotIn("stop_reason", pipe.runs[0])

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_turn_limit_allows_last_turn_batch_then_stops(self):
        pipe, _, messages, _ = self.smoke("baseline", tool="get_current_day", max_turns=1,
                                         batch=True, stopped=True)
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 2)
        self.assertEqual(len(messages[1]["tool_calls"]), 2)
        self.assertEqual(pipe.runs[0]["stop_reason"], "turn_limit_exceeded")

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_turn_limit_does_not_abort_official_attack_loop(self):
        pipe, _, _, _ = self.smoke("baseline", tool="get_current_day", max_turns=1,
                                  official="attack", stopped=True)
        self.assertEqual(len(pipe.runs), 2)
        self.assertTrue(all(r["stop_reason"] == "turn_limit_exceeded" for r in pipe.runs))

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_cli_turn_limit_reports_stops(self):
        self.smoke("baseline", tool="get_current_day", max_turns=1, official="cli", stopped=True)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_date_bound_clean_task_passes_official_utility(self):
        rules = [{"tool": "search_calendar_events", "decision": "allow", "predicate": {
            "op": "and", "args": [
                {"op": "eq", "field": "payload.query", "value": "Networking event"},
                {"op": "glob", "field": "payload.date", "value": "*-05-26"}]}}]
        pipe, _, _, requests = self.smoke("guarded", tool="search_calendar_events", rules=rules,
            args={"query": "Networking event", "date": self.env.calendar.current_day.isoformat()[:4] + "-05-26"},
            official=True, echo_result=True, expected_utility=True)
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 1)
        self.assertIn("Trusted simulation calendar date", str(requests[0]["messages"]))
        snapshot = json.loads(next((self.root / "out").glob("policy-*.json")).read_text())
        self.assertEqual(len(snapshot["date_bindings"]), 1)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_denied_extra_tool_still_allows_official_final_answer(self):
        date = self.env.calendar.current_day.isoformat()[:4] + "-05-26"
        rules = [{"tool": "search_calendar_events", "decision": "allow", "predicate": {
            "op": "and", "args": [
                {"op": "eq", "field": "payload.query", "value": "Networking event"},
                {"op": "eq", "field": "payload.date", "value": date}]}}]
        pipe, _, _, requests = self.smoke("guarded", tool="search_calendar_events", rules=rules,
            steps=[{"tool": "search_calendar_events", "arguments": {"query": "Networking event", "date": date}},
                   {"tool": "search_contacts_by_name", "arguments": {"query": "Emma Johnson"}}],
            official=True, stopped=False, echo_result="first", expected_utility=True)
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 1)
        self.assertEqual(pipe.runs[0]["counts"]["BLOCK"], 1)
        # The unauthorized lookup stays blocked, but existing authorized reads
        # remain available; the model can also finish using its earlier result.
        self.assertTrue(requests[-1].get("tools"))

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_final_answer_tool_proposal_never_executes(self):
        pipe, before, messages, requests = self.smoke("guarded", args={"filename": "fixture", "content": "x"},
            stopped=True, final_violation=True)
        self.assertEqual(pipe.runs[0]["stop_reason"], "final_answer_invalid")
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 0)
        self.assertEqual(before, self.env.model_dump())
        self.assertFalse(requests[-1].get("tools"))

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_real_sdk_guard_allows_read(self):
        pipe, _, _, _ = self.smoke("guarded", tool="get_current_day", rules=[{
            "tool": "get_current_day", "decision": "allow", "predicate": {"op": "true"}}])
        self.assertEqual(pipe.runs[0]["counts"]["ALLOW"], 1)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_official_evaluator_accepts_pi_pipeline(self):
        self.smoke("baseline", tool="get_current_day", official=True)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_official_attack_evaluator_accepts_pi_pipeline(self):
        self.smoke("baseline", tool="get_current_day", official="attack")

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_model_error_is_not_a_successful_defense(self):
        self.smoke("guarded", broken=True)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required")
    def test_cli_writes_official_results_and_provenance(self):
        self.smoke("baseline", tool="get_current_day", official="cli")


if __name__ == "__main__":
    unittest.main()
