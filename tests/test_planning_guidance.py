import copy
import unittest
from types import SimpleNamespace

from policy.planning import parameter_candidates, planning_instruction
from tests.test_agentdojo_pi import FixtureMixin


def rule(query, date):
    return {"tool": "search_calendar_events", "decision": "allow", "predicate": {
        "op": "and", "args": [{"op": "eq", "field": "payload.query", "value": query},
                                {"op": "eq", "field": "payload.date", "value": date}]}}


class GuidanceTests(FixtureMixin, unittest.TestCase):
    def test_exact_values_help_repair_without_expanding_authority(self):
        rules = [rule("Yoga Class", None)]
        original = copy.deepcopy(rules)
        host = self.host(rules=rules, intent_text="When is my next Yoga Class?")
        _, error = host.call("first", "search_calendar_events", {"query": "Yoga", "date": None})
        self.assertIn("ICB-CONFIRM", error)
        candidates = host.last_feedback["parameter_candidates"]
        self.assertEqual(candidates, [{"tool": "search_calendar_events",
                                      "exact_arguments": {"query": "Yoga Class", "date": None}}])
        result, error = host.call("fixed", "search_calendar_events", candidates[0]["exact_arguments"])
        self.assertIsNone(error)
        self.assertTrue(result)
        self.assertEqual(host.counts["executed"], 1)
        self.assertEqual(rules, original)

    def test_guidance_does_not_override_deny(self):
        rules = [rule("Yoga Class", None), {"tool": "search_calendar_events", "decision": "deny",
                                            "predicate": {"op": "true"}}]
        host = self.host(rules=rules)
        hint = parameter_candidates(host.rules, host.contracts)
        self.assertEqual(len(hint), 1)
        self.assertIn("ICB-BLOCK", host.call("blocked", hint[0]["tool"], hint[0]["exact_arguments"])[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_complex_predicates_are_never_flattened_or_partialized(self):
        contracts = {"search_calendar_events": SimpleNamespace(fields={"query": {}, "date": {}}, aliases={})}
        for predicate in ({"op": "or", "args": [rule("one", None)["predicate"], rule("two", None)["predicate"]]},
                          {"op": "and", "args": [rule("one", None)["predicate"],
                                                  {"op": "eq", "field": "target", "value": "other"}]},
                          {"op": "eq", "field": "payload.query", "value": {"$binding": "resource"}}):
            r = {"tool": "search_calendar_events", "decision": "allow", "predicate": predicate}
            self.assertEqual(parameter_candidates([r], contracts), [])

    def test_alternatives_remain_separate_and_conflicts_are_not_suggestions(self):
        host = self.host(rules=[rule("Yoga Class", None), rule("Lunch", "2024-05-15")])
        hints = parameter_candidates(host.rules, host.contracts)
        self.assertEqual(len(hints), 2)
        self.assertEqual(hints[0]["exact_arguments"], {"query": "Yoga Class", "date": None})
        conflict = rule("Yoga", None)
        conflict["predicate"]["args"].append({"op": "eq", "field": "payload.date", "value": "2024-05-15"})
        self.assertEqual(parameter_candidates([conflict], host.contracts), [])
        self.assertIn("not instructions", planning_instruction(host.rules, host.contracts))


if __name__ == "__main__":
    unittest.main()
