import unittest
from types import SimpleNamespace
from pydantic import BaseModel, Field
from attestation.hashing import object_hash
from policy.tool_contract import ToolContract


class Parameters(BaseModel):
    query: str
    scope: str | None = None
    notify: bool = False


def rule(**values):
    return {"tool": "lookup", "decision": "allow", "predicate": {"op": "and", "args": [
        {"op": "eq", "field": "payload." + k, "value": v} for k, v in values.items()]}}


class ToolContractTests(unittest.TestCase):
    def contract(self, **kwargs):
        return ToolContract("lookup", Parameters, **kwargs)

    def check(self, contract, rules, payload):
        normalized = contract.normalize(payload)
        action = SimpleNamespace(type="lookup", target=normalized["query"], payload=normalized)
        return contract.check(action, contract.complete_rules(rules), {"actions": ["lookup"]})

    def test_all_parameters_including_defaults_need_bounds(self):
        c = self.contract()
        decision = self.check(c, [rule(query="meeting")], {"query": "meeting"})
        self.assertEqual(decision["rule"], "contract.coverage")
        self.assertIn("scope", decision["reason"])
        self.assertIn("notify", decision["reason"])
        self.assertIsNone(self.check(c, [rule(query="meeting", scope=None, notify=False)], {"query": "meeting"}))

    def test_operator_declared_false_default_works_for_new_tool(self):
        c = self.contract(schema_hash=object_hash(Parameters.model_json_schema()), semantics={
            "notify": {"mode": "no_additional_effect", "values": [False], "reason": "False sends no notification"}})
        self.assertIsNone(self.check(c, [rule(query="meeting", scope=None)], {"query": "meeting"}))
        self.assertIsNotNone(self.check(c, [rule(query="meeting", scope=None)], {"query": "meeting", "notify": True}))
        # None scope is deliberately not inferred to be safe without explicit intent.
        self.assertEqual(self.check(c, [rule(query="meeting")], {"query": "meeting"})["verdict"], "CONFIRM")

    def test_schema_change_and_unreviewed_semantics_are_rejected(self):
        with self.assertRaises(ValueError):
            self.contract(schema_hash="old-schema")
        with self.assertRaises(ValueError):
            self.contract(semantics={"notify": {"mode": "intent_bound"}})

    def test_invalid_semantics_never_grant_authority(self):
        pin = object_hash(Parameters.model_json_schema())
        for semantics in ([], {"unknown": {"mode": "intent_bound"}},
                          {"notify": {"mode": "allow_any"}},
                          {"query": {"mode": "no_additional_effect", "values": [""], "reason": "bad"}},
                          {"notify": {"mode": "no_additional_effect", "values": [0], "reason": "bad"}},
                          {"notify": {"mode": "no_additional_effect", "values": [True], "reason": "bad"}}):
            with self.subTest(semantics=semantics), self.assertRaises(ValueError):
                self.contract(schema_hash=pin, semantics=semantics)

    def test_unknown_arguments_are_not_silently_dropped(self):
        with self.assertRaises(ValueError):
            self.contract().normalize({"query": "meeting", "approved": True})

    def test_dynamic_defaults_are_rejected(self):
        class Dynamic(BaseModel):
            values: list[str] = Field(default_factory=list)
        with self.assertRaises(ValueError):
            ToolContract("dynamic", Dynamic)

    def test_boolean_cannot_match_numeric_intent(self):
        decision = self.check(self.contract(), [rule(query="meeting", scope=None, notify=0)], {"query": "meeting"})
        self.assertEqual(decision["rule"], "contract.value_type")

    def test_rules_do_not_combine_into_unintended_parameter_pairs(self):
        rules = [rule(query="A", scope="one", notify=False), rule(query="B", scope="two", notify=False)]
        self.assertIsNotNone(self.check(self.contract(), rules, {"query": "A", "scope": "two"}))

    def test_loose_or_branch_is_not_complete_coverage(self):
        r = rule(query="meeting", scope=None)
        r["predicate"]["args"].append({"op": "or", "args": [
            {"op": "eq", "field": "payload.notify", "value": False}, {"op": "true"}]})
        self.assertEqual(self.check(self.contract(), [r], {"query": "meeting"})["rule"], "contract.coverage")

    def test_original_rules_immutable_and_no_new_tool_permission(self):
        c = self.contract()
        original = rule(query="meeting", scope=None, notify=False)
        completed = c.complete_rules([original])
        self.assertEqual(original["predicate"]["args"][1]["op"], "eq")
        self.assertEqual(completed[0]["predicate"]["args"][1]["op"], "in")
        self.assertIsNotNone(self.check(c, [], {"query": "meeting"}))

    def test_target_bound_to_same_argument_counts_as_coverage(self):
        c = self.contract(target_field="query")
        r = rule(scope=None, notify=False)
        r["predicate"]["args"].append({"op": "eq", "field": "target", "value": "meeting"})
        self.assertIsNone(self.check(c, [r], {"query": "meeting"}))


if __name__ == "__main__":
    unittest.main()
