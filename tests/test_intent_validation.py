import copy
import unittest
from pydantic import BaseModel
from policy.intent_validation import rule_semantic_errors, effect_consistency_errors, quarantine_invalid_allows
from policy.tool_contract import ToolContract
from tests.test_rule_validation import LookupParameters, eq, rule, conjunction
from tests.test_runtime_bindings import Lookup, Use, DECLARATION, RULE


class SemanticValidationTests(unittest.TestCase):
    def test_nested_binding_is_rejected_before_host_initialization(self):
        for value in ([{"$binding": "invented"}],
                      {"nested": {"$binding": "invented"}},
                      {"$binding": "outer", "source_arguments": {"query": {"$binding": "inner"}}}):
            with self.subTest(value=value):
                bad = rule(eq("payload.query", value))
                self.assertIn("invalid_runtime_reference", self.codes([bad]))
                valid = rule(conjunction(eq("payload.query", "x"), eq("payload.date", None)))
                compiled, removed, errors = quarantine_invalid_allows([valid, bad],
                    lambda rows: rule_semantic_errors(rows, self.contracts))
                self.assertEqual(compiled, [valid])
                self.assertEqual(len(removed), 1)
                self.assertFalse(errors)
                deny = {**bad, "decision": "deny"}
                compiled, removed, errors = quarantine_invalid_allows([valid, deny],
                    lambda rows: rule_semantic_errors(rows, self.contracts))
                self.assertEqual(compiled, [valid, deny])
                self.assertTrue(errors)
                self.assertFalse(removed)

    def test_quarantine_removes_only_bad_allow_and_preserves_all_denies(self):
        valid = rule(conjunction(eq("payload.query", "x"), eq("payload.date", None)))
        invalid = rule(eq("payload.date", "null"))
        deny = rule(eq("payload.query", "private"), decision="deny")
        original = [valid, invalid, deny]
        compiled, removed, errors = quarantine_invalid_allows(original,
            lambda rows: rule_semantic_errors(rows, self.contracts))
        self.assertEqual(compiled, [valid, deny])
        self.assertEqual(removed[0]["original_rule_index"], 1)
        self.assertEqual(removed[0]["rule"], invalid)
        self.assertFalse(errors)
        self.assertEqual(original, [valid, invalid, deny])
        from policy.symbolic import check_rules, action_fields
        for query in ("x", "private", "other"):
            for date in (None, "null", "2024-05-15"):
                fields = action_fields("lookup", query, {"query": query, "date": date})
                if check_rules("lookup", fields, compiled)[0] == "allow":
                    self.assertEqual(check_rules("lookup", fields, original)[0], "allow")

    def test_invalid_deny_and_all_invalid_allows_remain_failures(self):
        invalid = rule(eq("payload.date", "null"))
        validate = lambda rows: rule_semantic_errors(rows, self.contracts)
        rules, removed, errors = quarantine_invalid_allows([invalid], validate)
        self.assertEqual(errors, [{"code": "no_valid_allow_after_quarantine"}])
        bad_deny = {**invalid, "decision": "deny"}
        rules, removed, errors = quarantine_invalid_allows([bad_deny], validate)
        self.assertEqual(rules, [bad_deny])
        self.assertFalse(removed)
        self.assertTrue(errors)

    def test_allow_and_forbidden_effect_conflict_is_reported_not_removed(self):
        effects = {"forbidden_effects": ["external_communication"]}
        caps = {"lookup": {"effect_type": "external_communication"}}
        rules = [rule(eq("payload.query", "x"))]
        self.assertEqual(effect_consistency_errors(rules, effects, caps)[0]["code"],
                         "allowed_tool_has_forbidden_effect")
        self.assertEqual(effects["forbidden_effects"], ["external_communication"])
        self.assertFalse(effect_consistency_errors(rules, effects, {"lookup": {"effect_type": "read"}}))

    def setUp(self):
        self.contracts = {"lookup": ToolContract("lookup", LookupParameters)}

    def codes(self, rules, prompt=""):
        before = copy.deepcopy(rules)
        errors = rule_semantic_errors(rules, self.contracts, prompt=prompt)
        self.assertEqual(before, rules)
        return {e["code"] for e in errors}

    def test_null_is_not_string_and_no_coercion(self):
        self.assertIn("quoted_null_on_nullable_parameter", self.codes([rule(eq("payload.date", "null"))]))
        self.assertFalse(self.codes([rule(eq("payload.date", None))]))
        self.assertFalse(self.codes([rule(eq("payload.date", "null"))], 'Search for literal "null"'))
        self.assertIn("rule_value_type_mismatch", self.codes([rule(eq("payload.query", 123))]))

    def test_placeholder_but_not_user_literal_is_rejected(self):
        self.assertIn("unresolved_placeholder", self.codes([rule(eq("payload.query", "user_provided_id"))]))
        self.assertFalse(self.codes([rule(eq("payload.query", "user_provided_id"))], "Find user_provided_id"))

    def test_contradictory_bounds_and_allows_shadowed_by_deny(self):
        self.assertIn("contradictory_parameter_bounds", self.codes([
            rule(conjunction(eq("payload.query", "x"), eq("payload.query", "y")))]))
        allow = rule(eq("payload.query", "shared with alex"))
        deny = rule({"op": "glob", "field": "payload.query", "value": "*shared*"}, decision="deny")
        self.assertIn("allow_fully_shadowed_by_deny", self.codes([allow, deny]))

    def test_partial_overlap_and_wildcard_default_deny_are_valid(self):
        allow = rule({"op": "in", "field": "payload.query", "value": ["public", "private"]})
        deny = rule(eq("payload.query", "private"), decision="deny")
        self.assertFalse(self.codes([allow, deny]))
        self.assertFalse(self.codes([allow, rule({"op": "true"}, tool="*", decision="deny")]))

    def test_unknown_field_value_is_not_assumed_null_for_proof(self):
        self.assertFalse(self.codes([rule(eq("payload.query", "x")),
            rule(eq("payload.date", None), decision="deny")]))

    def test_in_constraints_validate_whole_list_argument_not_elements(self):
        class Parameters(BaseModel):
            recipients: list[str]
        self.contracts = {"lookup": ToolContract("lookup", Parameters)}
        self.assertFalse(self.codes([rule(eq("payload.recipients", ["a", "b"]))]))
        self.assertIn("rule_value_type_mismatch", self.codes([
            rule({"op": "in", "field": "payload.recipients", "value": ["a", "b"]})]))

    def test_binding_requires_known_name_target_and_source_authorization(self):
        contracts = {"custom_lookup": ToolContract("custom_lookup", Lookup),
                     "custom_use": ToolContract("custom_use", Use)}
        source = {"tool": "custom_lookup", "decision": "allow", "predicate": eq("payload.query", "report")}
        errors = rule_semantic_errors([RULE], contracts, bindings=DECLARATION)
        self.assertEqual(errors[0]["code"], "binding_missing_prerequisite_rule")
        self.assertFalse(rule_semantic_errors([source, RULE], contracts, bindings=DECLARATION))
        scoped = copy.deepcopy(RULE)
        scoped["predicate"]["value"]["source_arguments"] = {"query": "report"}
        self.assertFalse(rule_semantic_errors([source, scoped], contracts, bindings=DECLARATION))
        source["predicate"]["value"] = "other"
        self.assertEqual(rule_semantic_errors([source, scoped], contracts, bindings=DECLARATION)[0]["code"],
                         "binding_prerequisite_outside_policy")
        scoped["predicate"]["value"]["$binding"] = "invented"
        self.assertEqual(rule_semantic_errors([scoped], contracts, bindings=DECLARATION)[0]["code"],
                         "invalid_runtime_reference")
