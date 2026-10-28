import copy
import unittest
from types import SimpleNamespace

from pydantic import BaseModel
from attestation.hashing import object_hash
from policy.engine import PolicyEngine
from policy.semantic_action import SemanticAdapter
from policy.tool_contract import ToolContract


class ReadOne(BaseModel):
    path: str


class ReadTwo(BaseModel):
    file_path: str


def adapter(name="reader_a", parameters=ReadOne, source="path", **capability):
    contract = ToolContract(name, parameters, schema_hash=object_hash(parameters.model_json_schema()),
        roles={source: {"role": "resource", "reason": "Identifies the document accessed"}})
    caps = {"actions": [name], **capability}
    return SemanticAdapter(contract, {"version": 1, "operation": "read", "resource_type": "file",
        "fields": {source: "path"}, "effects": ["read"], "reason": "Reviewed file reader"}, caps)


class SemanticActionTests(unittest.TestCase):
    def test_tool_substitution_and_parameter_renaming_preserve_semantics(self):
        a = adapter().normalize({"path": "/project/report.pdf"})
        b = adapter("reader_b", ReadTwo, "file_path").normalize({"file_path": "/project/report.pdf"})
        self.assertEqual(a, b)
        self.assertNotIn("tool", a)
        self.assertEqual(a["parameters"], {"path": "/project/report.pdf"})

    def test_additional_effects_and_resources_do_not_disappear(self):
        plain = adapter().normalize({"path": "report.pdf"})
        for capability, expected in [({"process": "allowed"}, "process_execution"),
                                     ({"network": "allowed"}, "network_egress"),
                                     ({"persistence": "allowed"}, "persistence"),
                                     ({"external_share": "allowed"}, "external_communication")]:
            with self.subTest(capability=capability):
                broader = adapter(**capability)
                normalized = broader.normalize({"path": "report.pdf"})
                self.assertIn(expected, normalized["effect_upper_bound"])
                self.assertNotEqual(plain, normalized)
        self.assertNotEqual(plain, adapter().normalize({"path": "private-key.pem"}))
        self.assertTrue(adapter(process="allowed").execution_boundary())

    def test_destinations_and_content_are_preserved_without_generated_bounds(self):
        class Message(BaseModel):
            to: list[str]
            text: str
        schema = object_hash(Message.model_json_schema())
        contract = ToolContract("arbitrary_mailer", Message, schema_hash=schema, roles={
            "to": {"role": "destination", "reason": "Mail audience"},
            "text": {"role": "content", "reason": "Transmitted text"}})
        a = SemanticAdapter(contract, {"version": 1, "operation": "send", "resource_type": "email",
            "fields": {"to": "recipients", "text": "body"}, "effects": ["external_communication"],
            "reason": "Reviewed transport"}, {"external_share": "allowed"})
        value = a.normalize({"to": ["allowed@example.com", "extra@example.com"], "text": "Generated summary"})
        self.assertEqual(value["parameters"]["recipients"], ["allowed@example.com", "extra@example.com"])
        self.assertEqual(value["parameters"]["body"], "Generated summary")
        self.assertNotIn("allowed_values", str(value))

    def test_incomplete_ambiguous_or_capability_expanding_declarations_fail(self):
        base = adapter()
        for change in [{"fields": {}}, {"fields": {"path": "path", "extra": "x"}},
                       {"effects": ["external_communication"]}, {"operation": "invented"},
                       {"operation": []}, {"version": True}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                SemanticAdapter(base.contract, {**base.declaration, **change}, base.capability)
        with self.assertRaises(ValueError):
            base.normalize({})


class HardGateTests(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine("policy/policies")
        self.action = SimpleNamespace(type="new_reader", target="report.pdf", payload={"path": "report.pdf"})
        self.caps = {"actions": ["new_reader"]}

    def test_pass_is_not_authorization_and_old_missing_policy_behavior_remains(self):
        self.assertEqual(self.engine.check_hard(self.action, capability=self.caps)["verdict"], "PASS")
        self.assertEqual(self.engine.evaluate(self.action, "unknown", 0, capability=self.caps)["verdict"], "BLOCK")
        with self.assertRaises(ValueError):
            self.engine.check_hard(self.action, capability=self.caps, denies=[{
                "tool": "new_reader", "decision": "allow", "predicate": {"op": "true"}}])

    def test_capability_parameters_and_denies_are_independent_of_task_authority(self):
        self.assertEqual(self.engine.check_hard(self.action, capability=None)["verdict"], "BLOCK")
        cap = {**self.caps, "parameter_constraints": {"path": {"enum": ["other.pdf"]}}}
        self.assertEqual(self.engine.check_hard(self.action, capability=cap)["rule"], "capability.parameters")
        denial = {"tool": "new_reader", "decision": "deny", "predicate": {"op": "true"}}
        self.assertEqual(self.engine.check_hard(self.action, capability=self.caps, denies=[denial])["rule"], "symbolic.deny")

    def test_new_named_executable_is_not_misrepresented_as_read_only(self):
        caps = {**self.caps, "process": "allowed"}
        self.assertEqual(self.engine.check_hard(self.action, capability=caps)["rule"], "execution.review")
