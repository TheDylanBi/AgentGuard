import unittest
from types import SimpleNamespace
from pydantic import ValidationError
from gateway.api_schema import CapabilityDeclaration
from policy.parameter_constraints import check_constraints
from policy.engine import PolicyEngine
from policy.tool_capabilities import TOOL_CAPABILITIES


class ParameterConstraintTests(unittest.TestCase):
    def check(self, constraints, payload=None, target="test"):
        return check_constraints(SimpleNamespace(payload=payload or {}, target=target), constraints)

    def test_numeric_boundary_and_no_coercion(self):
        c = {"amount": {"minimum": 0, "maximum": 100}}
        for value in (0, 100, 99.5):
            self.assertIsNone(self.check(c, {"amount": value}))
        for value in (101, -1, True, "10", None, float("nan"), float("inf"), []):
            with self.subTest(value=repr(value)):
                self.assertIsNotNone(self.check(c, {"amount": value}))

    def test_required_optional_and_null(self):
        self.assertIsNotNone(self.check({"amount": {"maximum": 100}}))
        c = {"amount": {"maximum": 100, "required": False}}
        self.assertIsNone(self.check(c))
        self.assertIsNotNone(self.check(c, {"amount": None}))
        self.assertIsNotNone(self.check(c, {"amount": 101}))

    def test_exact_allowlist_and_type_sensitive_equality(self):
        c = {"to": {"type": "string", "enum": ["alice@example.test"]}}
        self.assertIsNone(self.check(c, {"to": "alice@example.test"}))
        for value in ("ALICE@example.test", "alice%40example.test", "alice@example.test,other@example.test", ["alice@example.test"]):
            self.assertIsNotNone(self.check(c, {"to": value}))
        self.assertIsNotNone(self.check({"x": {"enum": [1]}}, {"x": True}))
        self.assertIsNotNone(self.check({"x": {"const": True}}, {"x": 1}))

    def test_nested_fields_and_all_array_items(self):
        c = {"payload.payment.amount": {"type": "integer", "maximum": 100},
             "recipients": {"type": "array", "minItems": 1, "maxItems": 2,
                            "items": {"type": "string", "enum": ["a", "b"]}}}
        self.assertIsNone(self.check(c, {"payment": {"amount": 10}, "recipients": ["a", "b"]}))
        self.assertIsNotNone(self.check(c, {"payment": {"amount": 10}, "recipients": ["a", "evil"]}))
        self.assertIsNotNone(self.check(c, {"payment": {"amount": 10}, "recipients": []}))
        self.assertIsNotNone(self.check({"payload.p.x": {"type": "string", "required": False}}, {"p": []}))

    def test_target_and_length(self):
        self.assertIsNone(self.check({"target": {"const": "test"}}))
        c = {"text": {"type": "string", "minLength": 1, "maxLength": 3}}
        self.assertIsNone(self.check(c, {"text": "abc"}))
        self.assertIsNotNone(self.check(c, {"text": "abcd"}))

    def test_bad_declarations_rejected_at_registration_and_offline(self):
        bad = [None, [], {"x": {}}, {"x": {"type": None}}, {"x": {"maximum": "100"}},
               {"x": {"maximum": True}}, {"x": {"maximum": float("inf")}},
               {"x": {"pattern": ".*"}}, {"x": {"required": False}},
               {"x": {"type": "array", "items": {"format": "email"}}},
               {"x": {"minimum": 2, "maximum": 1}},
               {"x": {"exclusiveMinimum": 1, "maximum": 1}},
               {"x": {"enum": []}}, {"x": {"type": "number", "maxLength": 2}},
               {"x": {"type": "string"}, "payload.x": {"type": "string"}},
               {"payload.items.*": {"type": "string"}}]
        for c in bad:
            with self.subTest(constraints=c):
                with self.assertRaises(ValidationError):
                    CapabilityDeclaration(parameter_constraints=c)
                self.assertIsNotNone(self.check(c))

    def test_intent_cannot_expand_capability_even_without_rules_enabled(self):
        engine = PolicyEngine("policy/policies")
        a = SimpleNamespace(type="demo_transfer", target="test", payload={"amount": 101})
        caps = {"actions": [a.type], "parameter_constraints": {"amount": {"maximum": 100}}}
        rules = [{"tool": a.type, "decision": "allow", "predicate": {"op": "true"}}]
        for enabled in (True, False):
            r = engine.evaluate(a, "unknown", 0, capability=caps, rules=rules, enable_rules=enabled)
            self.assertEqual((r["verdict"], r["rule"]), ("BLOCK", "capability.parameters"))
        a.payload["amount"] = 100
        self.assertEqual(engine.evaluate(a, "unknown", 0, capability=caps, rules=rules)["verdict"], "ALLOW")

    def test_existing_tool_declarations_are_compatible(self):
        for name, caps in TOOL_CAPABILITIES.items():
            with self.subTest(tool=name):
                CapabilityDeclaration(**caps)


if __name__ == "__main__":
    unittest.main()
