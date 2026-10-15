import copy
import unittest

from pydantic import BaseModel

from policy.rule_validation import rule_schema_errors, repair_constraints_preserved
from policy.tool_contract import ToolContract


class LookupParameters(BaseModel):
    query: str
    date: str | None = None


class OtherParameters(BaseModel):
    query: str


def eq(field, value):
    return {"op": "eq", "field": field, "value": value}


def rule(predicate, tool="lookup", decision="allow"):
    return {"tool": tool, "decision": decision, "predicate": predicate}


def conjunction(*predicates):
    return {"op": "and", "args": list(predicates)}


class RuleValidationTests(unittest.TestCase):
    def setUp(self):
        self.contracts = {
            "lookup": ToolContract("lookup", LookupParameters, target_field="query",
                                   aliases={"search_text": "query"}),
            "other": ToolContract("other", OtherParameters, target_field="query"),
        }

    def test_schema_paths_and_declared_aliases_are_valid(self):
        rules = [rule(conjunction(eq("type", "lookup"), eq("target", "event"),
                                  eq("payload.query", "event"),
                                  eq("payload.date", "2024-05-26"),
                                  eq("payload.search_text", "event")))]
        self.assertEqual(rule_schema_errors(rules, self.contracts), [])

    def test_bare_unknown_and_nested_paths_rejected_for_allow_and_deny(self):
        for decision in ("allow", "deny"):
            for field in ("query", "date", "payload.missing", "payload.query.name"):
                with self.subTest(decision=decision, field=field):
                    errors = rule_schema_errors([rule(eq(field, "x"), decision=decision)],
                                                self.contracts)
                    self.assertEqual(errors[0]["code"], "unknown_field_path")
                    self.assertEqual(errors[0]["rule_index"], 0)
                    self.assertIn("payload.query", errors[0]["allowed_fields"])

    def test_wildcard_only_references_common_fields(self):
        self.assertEqual(rule_schema_errors([rule(eq("payload.query", "x"), tool="*",
                                                  decision="deny")], self.contracts), [])
        errors = rule_schema_errors([rule(eq("payload.date", "2024-05-26"), tool="*",
                                          decision="deny")], self.contracts)
        self.assertEqual(errors[0]["code"], "unknown_field_path")

    def test_unknown_tool_is_rejected(self):
        errors = rule_schema_errors([rule(eq("payload.query", "x"), tool="undeclared")],
                                    self.contracts)
        self.assertEqual(errors[0]["code"], "unknown_tool")

    def test_invalid_structure_is_rejected(self):
        for rules in (None, {}, [None], [rule({"op": "and", "args": []})],
                      [rule({"op": "not", "args": [eq("target", "x"), eq("target", "y")]})]):
            with self.subTest(rules=rules):
                self.assertEqual(rule_schema_errors(rules, self.contracts)[0]["code"],
                                 "invalid_rule_structure")

    def test_nonstr_tool_is_rejected_without_exception(self):
        for tool in ([], {}, 12):
            with self.subTest(tool=tool):
                self.assertTrue(rule_schema_errors([rule(eq("payload.query", "x"), tool=tool)],
                                                   self.contracts))

    def test_empty_rules_stay_empty_authority(self):
        self.assertEqual(rule_schema_errors([], self.contracts), [])

    def test_validation_never_rewrites_inputs_or_infers_coverage(self):
        rules = [rule(eq("query", "event")), rule(eq("payload.date", "2024-05-26"))]
        snapshot = copy.deepcopy(rules)
        self.assertTrue(rule_schema_errors(rules, self.contracts))
        self.assertEqual(rules, snapshot)
        # Schema validity is not a claim that a tool call is fully authorized.
        self.assertEqual(rule_schema_errors([rule(eq("payload.query", "event"))],
                                           self.contracts), [])

    def test_split_conditions_can_only_repair_to_conjunction(self):
        original = [rule(eq("query", "event")), rule(eq("date", "2024-05-26"))]
        repaired = [rule(conjunction(eq("payload.query", "event"),
                                     eq("payload.date", "2024-05-26")))]
        self.assertTrue(repair_constraints_preserved(original, repaired, self.contracts))
        still_split = [rule(eq("payload.query", "event")),
                       rule(eq("payload.date", "2024-05-26"))]
        self.assertFalse(repair_constraints_preserved(original, still_split, self.contracts))

    def test_repair_cannot_change_value_operator_or_add_constraint(self):
        original = [rule(eq("query", "event"))]
        replacements = [rule(eq("payload.query", "other event")),
                        rule({"op": "glob", "field": "payload.query", "value": "event"}),
                        rule(conjunction(eq("payload.query", "event"),
                                         eq("payload.date", "2024-05-26"))),
                        rule({"op": "true"})]
        for replacement in replacements:
            with self.subTest(replacement=replacement):
                self.assertFalse(repair_constraints_preserved(original, [replacement], self.contracts))

    def test_repair_cannot_add_tool_or_move_value_between_parameters(self):
        original = [rule(eq("query", "event"))]
        for replacement in ([rule(eq("payload.query", "event"), tool="other")],
                            [rule(eq("payload.date", "event"))]):
            with self.subTest(replacement=replacement):
                self.assertFalse(repair_constraints_preserved(original, replacement, self.contracts))

    def test_every_replacement_allow_retains_all_original_conditions(self):
        original = [rule(conjunction(eq("query", "event"), eq("date", "2024-05-26")))]
        complete = rule(conjunction(eq("payload.query", "event"), eq("payload.date", "2024-05-26")))
        self.assertFalse(repair_constraints_preserved(original,
            [complete, rule(eq("payload.query", "event"))], self.contracts))

    def test_repair_preserves_original_deny_exactly(self):
        deny = rule(eq("payload.query", "private"), decision="deny")
        original = [rule(eq("query", "event")), deny]
        repaired = rule(eq("payload.query", "event"))
        self.assertTrue(repair_constraints_preserved(original, [repaired, copy.deepcopy(deny)],
                                                     self.contracts))
        self.assertFalse(repair_constraints_preserved(original, [repaired], self.contracts))
        changed = rule(eq("payload.query", "different"), decision="deny")
        self.assertFalse(repair_constraints_preserved(original, [repaired, changed], self.contracts))

    def test_ambiguous_boolean_rewrites_are_not_supported(self):
        for operator in ("or", "not"):
            original = [rule({"op": operator, "args": [eq("query", "event")]})]
            self.assertFalse(repair_constraints_preserved(original,
                [rule(eq("payload.query", "event"))], self.contracts))
            self.assertFalse(repair_constraints_preserved([rule(eq("query", "event"))],
                [rule({"op": operator, "args": [eq("payload.query", "event")]})], self.contracts))

    def test_repair_equality_is_type_sensitive(self):
        for before, after in ((True, 1), (1, 1.0), ([True], [1]),
                              ({"value": False}, {"value": 0})):
            with self.subTest(before=before, after=after):
                self.assertFalse(repair_constraints_preserved([rule(eq("query", before))],
                    [rule(eq("payload.query", after))], self.contracts))

    def test_only_declared_aliases_and_parameters_can_gain_prefix(self):
        self.assertTrue(repair_constraints_preserved([rule(eq("search_text", "event"))],
            [rule(eq("payload.search_text", "event"))], self.contracts))
        self.assertFalse(repair_constraints_preserved([rule(eq("missing", "event"))],
            [rule(eq("payload.missing", "event"))], self.contracts))
        self.assertFalse(repair_constraints_preserved([rule(eq("target", "event"))],
            [rule(eq("payload.query", "event"))], self.contracts))

    def test_nested_and_reordering_is_equivalent_and_inputs_unchanged(self):
        original = [rule(conjunction(eq("query", "event"),
                                     conjunction(eq("date", "2024-05-26"))))]
        repaired = [rule(conjunction(eq("payload.date", "2024-05-26"),
                                     eq("payload.query", "event")))]
        snapshots = copy.deepcopy((original, repaired))
        self.assertTrue(repair_constraints_preserved(original, repaired, self.contracts))
        self.assertEqual((original, repaired), snapshots)

    def test_removing_allow_is_safe_but_never_removes_deny(self):
        self.assertTrue(repair_constraints_preserved([rule(eq("query", "event"))], [],
                                                     self.contracts))
        self.assertFalse(repair_constraints_preserved([rule(eq("payload.query", "event"),
                                                           decision="deny")], [], self.contracts))

    def test_nonfinite_values_fail_repair_closed(self):
        original = [rule(eq("query", float("nan")))]
        repaired = [rule(eq("payload.query", float("nan")))]
        self.assertFalse(repair_constraints_preserved(original, repaired, self.contracts))


if __name__ == "__main__":
    unittest.main()
