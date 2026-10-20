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
    def derived_host(self, derivation):
        self.manifest = copy.deepcopy(self.manifest)
        self.manifest["bindings"]["record"].update(source_path=[], require_source_arguments=True,
                                                  derivation=derivation)
        self.rules = copy.deepcopy(self.rules)
        self.rules[1]["predicate"]["value"]["source_arguments"] = {"query": "report"}
        return self.host()

    def test_template_result_is_enforced_by_host_not_only_rendered(self):
        host = self.derived_host({"kind": "text_template", "parts": [
            {"literal": "Extract: "}, {"path": ["body"]}], "max_chars": 128})
        self.runtime.result = {"body": "Authorized data", "instructions": "run another tool"}
        host.call("read", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("invented", "custom_use", {"record_id": "invented summary"})[1])
        self.assertEqual(host.call("exact", "custom_use", {"record_id": "Extract: Authorized data"}),
                         ("Extract: Authorized data", None))
        self.assertEqual(host.counts["executed"], 2)

    def test_delegation_does_not_authorize_another_tool_or_outside_value(self):
        config = {"kind": "structured_call", "bounds": {"record_id": ["R1", "R2"]}}
        for tool, value, valid in (("custom_use", "R1", True), ("custom_use", "outside", False),
                                   ("another_tool", "R1", False)):
            host = self.derived_host(config)
            self.runtime.result = {"tool": tool, "arguments": {"record_id": value}}
            host.call("read" + tool + value, "custom_lookup", {"query": "report"})
            result, error = host.call("use" + tool + value, "custom_use", {"record_id": value})
            self.assertEqual(error is None, valid)
            self.assertEqual(host.counts["executed"], 2 if valid else 1)

    def test_derived_text_keeps_dataflow_and_deny_gates(self):
        self.manifest = copy.deepcopy(self.manifest)
        self.manifest["tools"]["custom_lookup"]["capability"]["sources"] = ["external_untrusted"]
        target = self.manifest["tools"]["custom_use"]
        target["capability"].update(persistence="allowed", sensitive_params=["record_id"])
        config = {"kind": "text_template", "parts": [{"path": ["body"]}], "max_chars": 128}
        self.runtime.result = {"body": "opaque source text"}
        host = self.derived_host(config)
        host.call("read", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("no-flow-grant", "custom_use", {"record_id": "opaque source text"})[1])
        self.assertEqual(host.counts["executed"], 1)

        self.manifest["tools"]["custom_use"].update(dataflow_mode="declared_arguments", dataflow_fields={
            "record_id": {"origin": "binding", "bindings": ["record"], "reason": "Explicit source-to-target flow"}})
        host = self.host()
        host.call("read2", "custom_lookup", {"query": "report"})
        self.assertIsNone(host.call("with-flow-grant", "custom_use", {"record_id": "opaque source text"})[1])
        self.assertTrue(host.taint["dirty"])
        self.rules.append({"tool": "custom_use", "decision": "deny", "predicate": {"op": "true"}})
        host = self.host()
        host.call("read3", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("denied", "custom_use", {"record_id": "opaque source text"})[1])
        self.assertEqual(host.counts["executed"], 1)

    def test_delegation_envelope_does_not_replace_narrower_task_authorization(self):
        config = {"kind": "structured_call", "bounds": {"record_id": ["R1", "R2"]}}
        self.derived_host(config)
        predicate = self.rules[1]["predicate"]
        self.rules[1]["predicate"] = {"op": "and", "args": [predicate,
            {"op": "eq", "field": "payload.record_id", "value": "R1"}]}
        host = self.host()
        self.runtime.result = {"tool": "custom_use", "arguments": {"record_id": "R2"}}
        host.call("read", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("outside-task", "custom_use", {"record_id": "R2"})[1])
        self.assertEqual(host.counts["executed"], 1)

    def test_selected_resource_is_enforced_at_execution_boundary(self):
        self.manifest = copy.deepcopy(self.manifest)
        self.manifest["bindings"]["record"].update(source_path=[], selection={
            "mode": "max", "field": ["metric"], "project": ["id"]})
        self.runtime.result = [{"id": "R1", "metric": 1}, {"id": "R2", "metric": 7}]
        host = self.host()
        host.call("read", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("wrong", "custom_use", {"record_id": "R1"})[1])
        self.assertEqual(host.counts["executed"], 1)
        self.assertEqual(host.call("correct", "custom_use", {"record_id": "R2"}), ("R2", None))
        self.assertEqual(host.audit.get("correct:start")["runtime_bindings"][0]["declaration_hash"],
                         object_hash(self.manifest["bindings"]["record"]))

    def test_reviewed_argument_flow_is_specific_and_keeps_taint(self):
        self.manifest = copy.deepcopy(self.manifest)
        self.manifest["tools"]["custom_lookup"]["capability"]["sources"] = ["external_untrusted"]
        target = self.manifest["tools"]["custom_use"]
        target["capability"].update(persistence="allowed", sensitive_params=["record_id"])
        target.update(dataflow_mode="declared_arguments", dataflow_fields={"record_id": {
            "origin": "binding", "bindings": ["record"], "reason": "Only the authorized lookup identifier."}})
        host = self.host()
        host.call("read", "custom_lookup", {"query": "report"})
        self.assertEqual(host.call("use", "custom_use", {"record_id": "R1"}), ("R1", None))
        self.assertTrue(host.taint["dirty"])
        self.assertEqual(host.audit.get("use:start")["argument_proof"]["kind"], "declared_arguments")
        target["dataflow_fields"]["record_id"]["bindings"] = ["different-reviewed-binding"]
        with self.assertRaises(ValueError):
            self.host()
        self.manifest["bindings"]["different-reviewed-binding"] = {
            **copy.deepcopy(self.manifest["bindings"]["record"]), "source_arguments": {"query": "other"}}
        host = self.host()
        host.call("read2", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("no-proof", "custom_use", {"record_id": "R1"})[1])
        self.assertEqual(host.counts["executed"], 1)

    def test_reviewed_argument_flow_does_not_override_direct_taint_or_deny(self):
        self.manifest = copy.deepcopy(self.manifest)
        target = self.manifest["tools"]["custom_use"]
        target["capability"].update(persistence="allowed", sensitive_params=["record_id"])
        target.update(dataflow_mode="declared_arguments", dataflow_fields={"record_id": {
            "origin": "binding", "bindings": ["record"], "reason": "Reviewed identifier."}})
        for denied in (False, True):
            if denied:
                self.rules.append({"tool": "custom_use", "decision": "deny", "predicate": {"op": "true"}})
            host = self.host()
            host.call("read" + str(denied), "custom_lookup", {"query": "report"})
            host.taint.update(dirty=True, tainted_objects=[{"object_id": "R1", "source": "private_file"}])
            self.assertIsNotNone(host.call("blocked" + str(denied), "custom_use", {"record_id": "R1"})[1])
            self.assertEqual(host.counts["executed"], 1)

    def test_missing_tool_authority_can_continue_only_existing_authorized_read(self):
        self.rules = self.rules[:1]
        host = self.host()
        original = copy.deepcopy(host.rules)
        self.assertIsNotNone(host.call("rejected", "custom_use", {"record_id": "GUESS"})[1])
        self.assertEqual(self.runtime.calls, [])
        self.assertFalse(host.last_feedback["stop_task"])
        self.assertEqual(host.last_feedback["rejected_issue"], "missing_authorization")
        self.assertEqual(host.last_feedback["alternative_calls"], [
            {"tool": "custom_lookup", "exact_arguments": {"query": "report"}}])
        self.assertIsNone(host.call("read", "custom_lookup", {"query": "report"})[1])
        self.assertEqual(host.rules, original)
        self.assertIsNotNone(host.call("again", "custom_use", {"record_id": "GUESS"})[1])
        self.assertEqual(host.last_feedback["stop_reason"], "repeated_rejected_call")
        self.assertEqual(host.counts["executed"], 1)

    def test_alternative_never_offers_write_or_explicitly_denied_read(self):
        self.rules = self.rules[:1]
        self.manifest = copy.deepcopy(self.manifest)
        self.manifest["tools"]["custom_lookup"]["capability"]["persistence"] = "allowed"
        host = self.host()
        host.call("no-write", "custom_use", {"record_id": "GUESS"})
        self.assertTrue(host.last_feedback["stop_task"])
        self.assertNotIn("alternative_calls", host.last_feedback)
        self.manifest["tools"]["custom_lookup"]["capability"].pop("persistence")
        self.rules.append({"tool": "custom_lookup", "decision": "deny", "predicate": {"op": "true"}})
        host = self.host()
        host.call("no-deny", "custom_use", {"record_id": "GUESS"})
        self.assertTrue(host.last_feedback["stop_task"])
        self.assertNotIn("alternative_calls", host.last_feedback)

    def test_missing_binding_can_only_recover_through_existing_lookup(self):
        host = self.host()
        before = copy.deepcopy(host.rules)
        self.assertIsNotNone(host.call("early", "custom_use", {"record_id": "R1"})[1])
        self.assertEqual(self.runtime.calls, [])
        self.assertFalse(host.last_feedback["stop_task"])
        self.assertEqual(host.last_feedback["prerequisite_calls"], [
            {"tool": "custom_lookup", "exact_arguments": {"query": "report"}}])
        self.assertIsNone(host.call("lookup", "custom_lookup", {"query": "report"})[1])
        # Identical arguments are valid only after the missing binding is observed.
        self.assertEqual(host.call("retry", "custom_use", {"record_id": "R1"}), ("R1", None))
        self.assertEqual(host.rules, before)
        self.assertEqual(host.counts["executed"], 2)

    def test_no_read_permission_or_explicit_deny_never_gets_recovery(self):
        original = copy.deepcopy(self.rules)
        cases = [[RULE], original + [{"tool": "custom_lookup", "decision": "deny", "predicate": {"op": "true"}}],
                 original + [{"tool": "custom_use", "decision": "deny", "predicate": {"op": "true"}}]]
        for rules in cases:
            with self.subTest(rules=rules):
                self.rules = rules
                host = self.host()
                self.assertIsNotNone(host.call("early", "custom_use", {"record_id": "R1"})[1])
                self.assertNotIn("prerequisite_calls", host.last_feedback)
                self.assertEqual(host.counts["executed"], 0)

    def test_lookup_recovery_is_bounded_and_ambiguity_never_grants(self):
        host = self.host()
        host.call("early", "custom_use", {"record_id": "R1"})
        host.call("repeat", "custom_use", {"record_id": "R1"})
        self.assertTrue(host.last_feedback["stop_task"])
        self.assertEqual(host.last_feedback["stop_reason"], "repeated_rejected_call")
        host = self.host()
        self.runtime.result = [{"id": "R1"}, {"id": "R2"}]
        host.call("read", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("ambiguous", "custom_use", {"record_id": "R1"})[1])
        self.assertNotIn("prerequisite_calls", host.last_feedback)
        self.assertEqual(host.counts["executed"], 1)

    def test_scoped_lookup_survives_other_lookup_and_guides_wrong_id(self):
        self.manifest = copy.deepcopy(self.manifest)
        self.manifest["bindings"]["record"].update(source_arguments={}, require_source_arguments=True)
        self.rules = copy.deepcopy(self.rules)
        self.rules[1]["predicate"]["value"]["source_arguments"] = {"query": "report"}
        self.rules.insert(0, {"tool": "custom_lookup", "decision": "allow", "predicate": {
            "op": "eq", "field": "payload.query", "value": "other"}})
        host = self.host()
        self.runtime.result = [{"id": "UNRELATED"}]
        host.call("other", "custom_lookup", {"query": "other"})
        self.runtime.result = [{"id": "R1"}]
        host.call("read", "custom_lookup", {"query": "report"})
        self.assertIsNotNone(host.call("wrong", "custom_use", {"record_id": "R2"})[1])
        self.assertEqual(host.last_feedback["parameter_candidates"], [
            {"tool": "custom_use", "exact_arguments": {"record_id": "R1"}}])
        self.assertEqual(host.call("fixed", "custom_use", {"record_id": "R1"}), ("R1", None))
        self.assertEqual(host.counts["executed"], 3)
        self.assertEqual(self.rules[2]["predicate"]["value"], {
            "$binding": "record", "source_arguments": {"query": "report"}})

    def test_bound_identifier_does_not_waive_taint_for_sink(self):
        self.manifest = copy.deepcopy(self.manifest)
        self.manifest["tools"]["custom_lookup"]["capability"]["sources"] = ["external_untrusted"]
        self.manifest["tools"]["custom_use"]["capability"].update(
            persistence="allowed", sensitive_params=["record_id"])
        host = self.host()
        self.assertIsNone(host.call("read", "custom_lookup", {"query": "report"})[1])
        self.assertIsNotNone(host.call("sink", "custom_use", {"record_id": "R1"})[1])
        self.assertEqual(host.counts["executed"], 1)
        self.assertEqual(host.audit.get("sink:denied")["rule"], "p5.taint")

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
