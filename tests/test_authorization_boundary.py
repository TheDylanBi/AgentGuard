import copy
import unittest
from unittest.mock import patch
from pydantic import BaseModel
from attestation.hashing import object_hash
from policy.authorization_boundary import compile_boundary
from policy.tool_contract import ToolContract
from policy.runtime_bindings import validate_reference
from policy import symbolic


class Arguments(BaseModel):
    target: str
    text: str
    enabled: bool = False


class BoundaryTests(unittest.TestCase):
    def test_generator_uses_explicit_boundary_envelope(self):
        from policy.intent_anchor import anchor_boundary_llm
        with patch("policy.intent_anchor._json_response", return_value={"version": 1, "grants": [], "denies": []}) as response:
            result = anchor_boundary_llm("Read the requested item", tools_hint='{"tools":[]}')
        system, user, schema = response.call_args.args
        self.assertIn("unresolved", system)
        self.assertIn("never supply or change", system)
        self.assertIn("Read the requested item", user)
        self.assertEqual(set(schema["required"]), {"version", "grants", "denies"})
        self.assertEqual(result["grants"], [])

    def setUp(self):
        self.contract = ToolContract("custom", Arguments, schema_hash=object_hash(Arguments.model_json_schema()),
            roles={"target": {"role": "destination", "reason": "Audience"},
                   "text": {"role": "content", "reason": "Stored data"}})
        self.contracts = {"custom": self.contract}
        self.grant = {"tool": "custom", "purpose": "User-authorized operation", "parameters": {
            "target": {"kind": "values", "values": ["allowed"]},
            "text": {"kind": "values", "values": ["exact"]},
            "enabled": {"kind": "values", "values": [False]}}}
        self.boundary = {"version": 1, "grants": [self.grant], "denies": []}

    def test_complete_boundary_compiles_and_preserves_parameter_combination(self):
        original = copy.deepcopy(self.boundary)
        rules, report = compile_boundary(self.boundary, self.contracts, {})
        fields = symbolic.action_fields("custom", "allowed", {"target": "allowed", "text": "exact", "enabled": False})
        self.assertEqual(symbolic.check_rules("custom", fields, rules)[0], "allow")
        fields["payload.target"] = "outside"
        self.assertNotEqual(symbolic.check_rules("custom", fields, rules)[0], "allow")
        self.assertEqual(report["grants"][0]["parameters"]["text"]["role"], "content")
        self.assertEqual(self.boundary, original)

    def test_unresolved_never_creates_partial_allow_and_keeps_deny(self):
        self.grant["parameters"]["text"] = {"kind": "unresolved", "reason": "Missing approved source"}
        deny = {"tool": "custom", "decision": "deny", "predicate": {"op": "true"}}
        self.boundary["denies"] = [deny]
        rules, report = compile_boundary(self.boundary, self.contracts, {})
        self.assertEqual(rules, [deny])
        self.assertFalse(report["grants"][0]["executable"])
        self.assertEqual(report["unresolved"][0]["parameters"][0]["field"], "text")

    def test_models_cannot_reclassify_omit_or_coerce_parameters(self):
        for field, value in (("enabled", {"kind": "values", "values": [0]}),
                             ("text", {"kind": "free_text"}),
                             ("text", {"kind": "values", "values": ["x"], "role": "content"})):
            boundary = copy.deepcopy(self.boundary)
            boundary["grants"][0]["parameters"][field] = value
            with self.assertRaises(ValueError):
                compile_boundary(boundary, self.contracts, {})
        del self.grant["parameters"]["enabled"]
        with self.assertRaises(ValueError):
            compile_boundary(self.boundary, self.contracts, {})

    def test_invalid_deny_is_fatal_even_with_unresolved_allow(self):
        self.boundary["denies"] = [{"tool": "custom", "decision": "allow", "predicate": {"op": "true"}}]
        with self.assertRaises(ValueError):
            compile_boundary(self.boundary, self.contracts, {})

    def test_binding_must_match_parameter_and_execution_role_forbids_external_code(self):
        spec = {"target_tool": "custom", "target_field": "text", "source_tool": "custom", "source_arguments": {}}
        reference = {"$binding": "source"}
        self.grant["parameters"]["text"] = {"kind": "binding", "reference": reference}
        rules, _ = compile_boundary(self.boundary, self.contracts, {"source": spec})
        self.assertEqual(rules[0]["predicate"]["args"][1]["value"], reference)
        bad = {**spec, "target_field": "target"}
        with self.assertRaises(ValueError):
            compile_boundary(self.boundary, self.contracts, {"source": bad})
        execution = ToolContract("custom", Arguments, schema_hash=object_hash(Arguments.model_json_schema()),
                                roles={"text": {"role": "execution", "reason": "Interpreted by executor"}})
        with self.assertRaises(ValueError):
            compile_boundary(self.boundary, {"custom": execution}, {"source": spec})
        with self.assertRaises(ValueError):
            validate_reference(reference, {"source": spec}, {"custom": execution})

    def test_roles_require_reviewed_schema_and_unknown_stays_control(self):
        self.assertEqual(self.contract.fields["enabled"]["role"], "control")
        with self.assertRaises(ValueError):
            ToolContract("custom", Arguments, roles={"text": {"role": "content", "reason": "data"}})
        with self.assertRaises(ValueError):
            ToolContract("custom", Arguments, schema_hash=object_hash(Arguments.model_json_schema()),
                         target_field="target", roles={"target": {"role": "content", "reason": "incorrect"}})

    def test_separate_grants_do_not_cross_product_values(self):
        second = copy.deepcopy(self.grant)
        second["parameters"]["target"]["values"] = ["second"]
        second["parameters"]["text"]["values"] = ["second text"]
        self.boundary["grants"].append(second)
        rules, _ = compile_boundary(self.boundary, self.contracts, {})
        fields = symbolic.action_fields("custom", "allowed", {"target": "allowed", "text": "second text", "enabled": False})
        self.assertNotEqual(symbolic.check_rules("custom", fields, rules)[0], "allow")
