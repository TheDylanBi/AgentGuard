"""Real NTFS resources + gateway ticket/role checks; no model/network calls."""
import asyncio
import os
from pathlib import Path
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi import HTTPException
from adapters.sdk import ICBGuardClient, AuthorizeResult, AuthorizationBlocked, guard
from execution.files import BoundFile, ResourceRejected, MAX_BYTES
from gateway import config, server as gs
from gateway.api_schema import Action, ConfirmRequest
from tests import test_security_hardening as base
from tests.test_security_hardening import http_call


@unittest.skipUnless(os.name == "nt", "Real handle tests require Windows NTFS")
class ControlledExecutionTests(unittest.TestCase):
    register = base.SecurityHardeningTests.register
    request = base.SecurityHardeningTests.request
    consume_request = base.SecurityHardeningTests.consume_request

    def setUp(self):
        base.SecurityHardeningTests.setUp(self)
        p = patch.object(config, "CONTROLLED_EXECUTION", True)
        p.start()
        self.addCleanup(p.stop)
        Path(self.path).write_text("original", encoding="utf-8")

    def write_request(self, content="new", path=None):
        target = path or self.path
        self.cert = self.register({"actions": ["write_file"],
                                   "filesystem_write": [str(self.allowed) + "/*"]})
        gs.SESSION_POLICIES["s"]["rules"] = [{"tool": "write_file", "decision": "allow", "predicate": {
            "op": "and", "args": [{"op": "eq", "field": "target", "value": target},
                                  {"op": "eq", "field": "payload.content", "value": content}]}}]
        return self.request(target, action="write_file", payload={"content": content})

    def authorize_call(self, req):
        result = gs.authorize(req)
        self.assertEqual(result.verdict, "ALLOW", result.reason)
        self.assertEqual(result.execution_mode, "controlled")
        return self.consume_request(req, result)

    def test_read_and_single_use(self):
        req = self.authorize_call(self.request())
        self.assertEqual(gs.execute(req)["output"]["content"], "original")
        with self.assertRaises(HTTPException):
            gs.execute(req)

    def test_overwrite_utf8_and_truncate(self):
        req = self.authorize_call(self.write_request("你好"))
        self.assertEqual(gs.execute(req)["output"], {"bytes_written": 6})
        self.assertEqual(Path(self.path).read_bytes(), "你好".encode("utf-8"))

    def test_create_and_empty_write(self):
        req = self.authorize_call(self.write_request("", self.other))
        self.assertFalse(Path(self.other).exists())  # authorization has no write effect
        gs.execute(req)
        self.assertEqual(Path(self.other).read_bytes(), b"")

    def test_modified_content_invalidates_ticket_even_if_timestamp_restored(self):
        req = self.authorize_call(self.request())
        original = Path(self.path).stat()
        Path(self.path).write_text("modified", encoding="utf-8")
        os.utime(self.path, ns=(original.st_atime_ns, original.st_mtime_ns))
        with self.assertRaises(HTTPException) as error:
            gs.execute(req)
        self.assertEqual(error.exception.status_code, 409)

    def test_identical_replacement_invalidates_identity(self):
        req = self.authorize_call(self.request())
        replacement = self.allowed / "replacement.txt"
        replacement.write_text("original", encoding="utf-8")
        os.replace(replacement, self.path)
        with self.assertRaises(HTTPException):
            gs.execute(req)

    def test_write_does_not_clobber_concurrent_change(self):
        req = self.authorize_call(self.write_request())
        Path(self.path).write_text("other writer", encoding="utf-8")
        with self.assertRaises(HTTPException):
            gs.execute(req)
        self.assertEqual(Path(self.path).read_text(), "other writer")

    def test_new_file_inserted_before_execute_is_not_overwritten(self):
        req = self.authorize_call(self.write_request(path=self.other))
        Path(self.other).write_text("inserted", encoding="utf-8")
        with self.assertRaises(HTTPException):
            gs.execute(req)
        self.assertEqual(Path(self.other).read_text(), "inserted")

    def test_create_new_race_after_last_check_never_overwrites(self):
        req = self.authorize_call(self.write_request(path=self.other))
        run = BoundFile.run
        def raced(bound):
            Path(self.other).write_text("racer", encoding="utf-8")
            return run(bound)
        with patch.object(BoundFile, "run", raced):
            with self.assertRaises(HTTPException):
                gs.execute(req)
        self.assertEqual(Path(self.other).read_text(), "racer")
        self.assertNotIn(req.ticket, gs.EXECUTION_TICKETS)

    def test_handles_prevent_file_write_delete_and_parent_rename(self):
        with BoundFile(Action(type="read_file", target=self.path)) as bound:
            for action in (lambda: Path(self.path).write_text("race"),
                           lambda: Path(self.path).unlink(),
                           lambda: self.allowed.rename(self.root / "moved")):
                with self.assertRaises(OSError):
                    action()
            self.assertEqual(bound.run()["content"], "original")
        # All handles are released after the operation.
        Path(self.path).write_text("released", encoding="utf-8")

    def test_hard_link_rejected(self):
        os.link(self.path, self.other)
        self.assertEqual(gs.authorize(self.request()).decision_rule, "executor.resource")

    def test_metadata_hard_link_added_while_open_is_rechecked(self):
        # Windows sharing does not exclude metadata-only link creation. A
        # separate OS identity/ACL is required against that concurrent actor.
        action = Action(type="write_file", target=self.path, payload={"content": "new"})
        with BoundFile(action) as bound:
            os.link(self.path, self.other)
            with self.assertRaises(ResourceRejected):
                bound.run()
        self.assertEqual(Path(self.path).read_text(), "original")

    def test_junction_in_path_is_rejected(self):
        import _winapi
        junction = self.root / "junction"
        _winapi.CreateJunction(str(self.allowed), str(junction))
        self.addCleanup(os.rmdir, junction)
        with self.assertRaises(ResourceRejected):
            BoundFile(Action(type="read_file", target=str(junction / "one.txt")))

    def test_concurrent_execution_at_most_once(self):
        req = self.authorize_call(self.write_request())
        def attempt(_):
            try:
                return gs.execute(req)["status"] == "executed"
            except HTTPException:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(attempt, range(2))), 1)

    def test_changed_resource_invalidates_approval(self):
        Path(self.other).write_text("reviewed", encoding="utf-8")
        req = self.request(self.other)  # outside intent: requires approval
        result = gs.authorize(req)
        self.assertEqual(result.verdict, "CONFIRM")
        approved = gs.confirm(ConfirmRequest(token=result.confirm_token, approve=True))
        Path(self.other).write_text("changed", encoding="utf-8")
        req.approval_ticket = approved["ticket"]
        result = gs.authorize(req)
        self.assertEqual(result.verdict, "BLOCK")
        self.assertEqual(result.decision_rule, "executor.resource")

    def test_unchanged_resource_approval_executes(self):
        Path(self.other).write_text("reviewed", encoding="utf-8")
        req = self.request(self.other)
        result = gs.authorize(req)
        approved = gs.confirm(ConfirmRequest(token=result.confirm_token, approve=True))
        req.approval_ticket = approved["ticket"]
        call = self.authorize_call(req)
        self.assertEqual(gs.execute(call)["output"]["content"], "reviewed")

    def test_changed_payload_consumes_ticket_without_writing(self):
        req = self.authorize_call(self.write_request())
        req.action.payload["content"] = "tampered"
        with self.assertRaises(HTTPException):
            gs.execute(req)
        self.assertEqual(Path(self.path).read_text(), "original")
        self.assertNotIn(req.ticket, gs.EXECUTION_TICKETS)

    def test_no_client_execution_or_mode_downgrade(self):
        req = self.authorize_call(self.request())
        with self.assertRaises(HTTPException):
            gs.consume(req)
        with patch.object(config, "CONTROLLED_EXECUTION", False):
            with self.assertRaises(HTTPException):
                gs.consume(req)

    def test_unsupported_operation_and_arguments_blocked(self):
        for req in (self.request(action="click"), self.request(payload={"offset": 1}),
                    self.request(payload={"path": self.other}),
                    self.request(action="shell")):
            result = gs.authorize(req)
            self.assertEqual(result.verdict, "BLOCK")
            self.assertEqual(result.decision_rule, "executor.unsupported")

    def test_invalid_paths_and_protected_files(self):
        for path in ("relative.txt", r"\\server\share\x", r"C:\a\..\x", r"C:\NUL",
                     r"C:\x:stream", r"C:\x. "):
            with self.assertRaises(ResourceRejected):
                BoundFile(Action(type="read_file", target=path))
        with self.assertRaises(ResourceRejected):
            BoundFile(Action(type="read_file", target=self.path), protected=[self.allowed])

    def test_oversize_and_invalid_text_fail_closed(self):
        Path(self.path).write_bytes(b"x" * (MAX_BYTES + 1))
        self.assertEqual(gs.authorize(self.request()).verdict, "BLOCK")
        Path(self.path).write_bytes(b"\xff")
        self.assertEqual(gs.authorize(self.request()).verdict, "BLOCK")

    def test_role_enforcement_and_real_route(self):
        req = self.authorize_call(self.request()).model_dump()
        for token in ("", "intent-token", "approver-token", "admin-token"):
            self.assertEqual(asyncio.run(http_call("/execute", req, token))[0], 403)
        status, data = asyncio.run(http_call("/execute", req, "executor-token"))
        self.assertEqual(status, 200)
        self.assertEqual(data["output"]["content"], "original")

    def test_revocation_and_new_epoch_block_execution(self):
        req = self.authorize_call(self.request())
        self.register(self.caps, implementation="v2")
        with self.assertRaises(HTTPException):
            gs.execute(req)
        cert = self.register(self.caps, tool="new-tool")
        req = self.authorize_call(self.request(cert=cert, tool="new-tool"))
        gs._reset_session_policy("s", {"rules": []})
        with self.assertRaises(HTTPException):
            gs.execute(req)

    def test_audit_failure_prevents_write(self):
        req = self.authorize_call(self.write_request())
        with patch.object(gs.log, "append", side_effect=OSError("audit unavailable")):
            with self.assertRaises(OSError):
                gs.execute(req)
        self.assertEqual(Path(self.path).read_text(), "original")

    def test_failure_is_single_attempt_and_audited(self):
        req = self.authorize_call(self.write_request())
        with patch.object(BoundFile, "run", side_effect=OSError("failed")) as run:
            for _ in range(2):
                with self.assertRaises(HTTPException):
                    gs.execute(req)
            self.assertEqual(run.call_count, 1)
        self.assertIn("execution_failed", gs.log.path.read_text())

    def test_sdk_never_calls_local_function_for_controlled_ticket(self):
        client = ICBGuardClient()
        result = AuthorizeResult("ALLOW", "ok", execution_mode="controlled")
        with patch.object(client, "authorize", return_value=result), \
                patch.object(client, "execute", return_value={"content": "remote"}) as execute:
            def callback(target):
                self.fail("Local callback must never execute")
            self.assertEqual(guard(client, "tool", "read_file")(callback)(self.path), {"content": "remote"})
            execute.assert_called_once_with(result)
        with patch.object(client, "authorize", return_value=result), \
                patch.object(client, "execute", side_effect=OSError("connection lost")):
            with self.assertRaises(OSError):
                guard(client, "tool", "read_file")(callback)(self.path)
        with self.assertRaises(AuthorizationBlocked):
            client.consume(result)

    def test_production_always_requires_controlled_execution(self):
        with patch.object(config, "DEV_MODE", False), patch.object(config, "CONTROLLED_EXECUTION", False):
            self.assertTrue(config.controlled_execution_enabled())
            with self.assertRaises(HTTPException):
                gs.consume(self.authorize_call(self.request()))


if __name__ == "__main__":
    unittest.main()
