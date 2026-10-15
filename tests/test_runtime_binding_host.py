"""New tools integrate by schema/declaration without an engine name branch."""
import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from pydantic import BaseModel
from attestation.signer import Signer
from attestation.log import CertificateLog
from attestation.hashing import object_hash
from adapters.agentdojo_pi.host import SimulationHost, load_manifest
from tests.test_runtime_bindings import Lookup, Use, DECLARATION, RULE
from tests.test_agentdojo_pi import FixtureMixin


class Env(BaseModel):
    version: int = 1


class Runtime:
    functions = {"custom_lookup": SimpleNamespace(parameters=Lookup), "custom_use": SimpleNamespace(parameters=Use)}
    def __init__(self):
        self.calls = []
        self.result = [{"id": "R1"}]
    def run_function(self, env, name, arguments):
        self.calls.append((name, copy.deepcopy(arguments)))
        return (self.result if name == "custom_lookup" else arguments["record_id"]), None


class BindingHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.runtime, self.env = Runtime(), Env()
        self.manifest = {"version": 1, "suite": "custom", "bindings": DECLARATION,
            "tools": {name: {"capability": {"actions": [name]},
                "schema_hash": object_hash(f.parameters.model_json_schema())} for name, f in self.runtime.functions.items()}}
        self.rules = [{"tool": "custom_lookup", "decision": "allow", "predicate": {
            "op": "eq", "field": "payload.query", "value": "report"}}, RULE]

    def host(self):
        signer = Signer(self.root / "key", self.root / "public")
        return SimulationHost(self.runtime, self.env, self.manifest, signer,
            CertificateLog(self.root / "audit.jsonl", signer=signer), mode="guarded", rules=self.rules)

    def test_new_tools_complete_lookup_then_use_with_signed_binding_audit(self):
        host = self.host()
        self.assertIsNone(host.call("read", "custom_lookup", {"query": "report"})[1])
        self.assertEqual(host.call("use", "custom_use", {"record_id": "R1"}), ("R1", None))
        self.assertEqual(host.rules, self.rules)
        binding = host.audit.get("use:start")["runtime_bindings"][0]
        self.assertEqual(binding["source_call_id"], "read")
        self.assertEqual(host.counts["executed"], 2)
        self.assertIsNotNone(host.call("reuse", "custom_use", {"record_id": "R1"})[1])
        self.assertEqual(host.counts["executed"], 2)

    def test_unobserved_or_wrong_id_never_executes(self):
        host = self.host()
        self.assertIsNotNone(host.call("forged", "custom_use", {"record_id": "R1"})[1])
        self.assertEqual(self.runtime.calls, [])
        host = self.host()
        host.call("read2", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("wrong", "custom_use", {"record_id": "R2"})[1])
        self.assertEqual(host.counts["executed"], 1)

    def test_environment_change_and_explicit_deny_still_block(self):
        host = self.host()
        host.call("read", "custom_lookup", {"query": "report"})
        self.env.version += 1
        self.assertIsNotNone(host.call("stale", "custom_use", {"record_id": "R1"})[1])
        self.rules.append({"tool": "custom_use", "decision": "deny", "predicate": {"op": "true"}})
        host = self.host()
        host.call("read2", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("denied", "custom_use", {"record_id": "R1"})[1])
        self.assertEqual(host.audit.get("denied:denied")["rule"], "symbolic.deny")

    def test_hard_parameter_constraint_wins_over_bound_value(self):
        self.manifest["tools"]["custom_use"]["capability"]["parameter_constraints"] = {"record_id": {"enum": ["R2"]}}
        host = self.host()
        host.call("read", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("hard", "custom_use", {"record_id": "R1"})[1])
        self.assertEqual(host.audit.get("hard:denied")["rule"], "capability.parameters")


class WorkspaceBindingTests(FixtureMixin, unittest.TestCase):
    def test_official_file_lookup_binds_only_returned_file(self):
        file = next(iter(self.env.cloud_drive.files.values()))
        rules = [
            {"tool": "search_files_by_filename", "decision": "allow", "predicate": {
                "op": "eq", "field": "payload.filename", "value": file.filename}},
            {"tool": "get_file_by_id", "decision": "allow", "predicate": {
                "op": "eq", "field": "payload.file_id", "value": {"$binding": "selected_file_read"}}}]
        host = self.host(rules=rules)
        value, error = host.call("lookup", "search_files_by_filename", {"filename": file.filename})
        self.assertIsNone(error)
        self.assertEqual(len(value), 1)
        self.assertIsNone(host.call("read", "get_file_by_id", {"file_id": str(file.id_)})[1])
        self.assertEqual(host.counts["executed"], 2)
        self.assertTrue(host.taint["dirty"])
