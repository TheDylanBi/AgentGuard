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
    def test_reviewed_tool_notes_do_not_create_authority(self):
        from adapters.agentdojo_pi.host import tool_description
        name = "list_files"
        description = tool_description(self.runtime.functions[name], self.manifest["tools"][name])
        self.assertIn("shared_with", description)
        host = self.host(rules=[])
        self.assertIsNotNone(host.call("unauthorized", name, {})[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_unpinned_or_malformed_usage_notes_rejected(self):
        import json
        from adapters.agentdojo_pi.host import load_manifest
        for bad in ("not a list", [""], [1], ["x" * 801]):
            manifest = copy.deepcopy(self.manifest)
            manifest["tools"]["list_files"]["usage_notes"] = bad
            path = self.root / "bad-manifest.json"
            path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "Usage notes"):
                load_manifest(path, self.runtime)
        manifest = copy.deepcopy(self.manifest)
        del manifest["tools"]["list_files"]["schema_hash"]
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "Usage notes"):
            load_manifest(path, self.runtime)

    def test_array_and_optional_alternatives_enable_real_calendar_repair(self):
        args = {"title": "Lunch", "start_time": "2024-05-19 12:00",
                "end_time": "2024-05-19 13:00", "description": "Catch up over lunch",
                "participants": ["sarah.connor@gmail.com"]}
        rules = [{"tool": "create_calendar_event", "decision": "allow", "predicate": {
            "op": "and", "args": [{"op": "eq", "field": "payload." + k, "value": v}
                                      for k, v in args.items()]}}]
        host = self.host(rules=rules, effect_profile={"allowed_recipients": ["sarah.connor@gmail.com"]})
        _, error = host.call("wrong", "create_calendar_event", {**args, "location": "Invented place"})
        self.assertIsNotNone(error)
        self.assertEqual(host.counts["executed"], 0)
        hints = host.last_feedback["parameter_candidates"]
        self.assertEqual(len(hints), 2)
        self.assertEqual(hints[0]["exact_arguments"]["participants"], args["participants"])
        self.assertEqual({h["exact_arguments"]["location"] for h in hints}, {None, ""})
        _, error = host.call("corrected", "create_calendar_event", hints[0]["exact_arguments"])
        self.assertIsNone(error)
        self.assertEqual(host.counts["executed"], 1)

    def test_nested_values_are_preserved_but_bindings_are_never_exposed(self):
        contracts = {"custom": SimpleNamespace(fields={"value": {}}, aliases={})}
        value = {"recipients": ["one@example.test"], "options": {"notify": False}}
        def sample(v):
            return {"tool": "custom", "decision": "allow", "predicate": {
                "op": "eq", "field": "payload.value", "value": v}}
        rules = [sample(value)]
        hints = parameter_candidates(rules, contracts)
        self.assertEqual(hints[0]["exact_arguments"]["value"], value)
        hints[0]["exact_arguments"]["value"]["recipients"].append("extra")
        self.assertEqual(value["recipients"], ["one@example.test"])
        self.assertEqual(parameter_candidates([sample({"nested": [{"$binding": "pending"}]})], contracts), [])

    def test_finite_intersections_are_typed_and_large_products_omitted(self):
        contracts = {"custom": SimpleNamespace(fields={"x": {}, "y": {}}, aliases={})}
        def candidate(atoms):
            return parameter_candidates([{"tool": "custom", "decision": "allow",
                "predicate": {"op": "and", "args": atoms}}], contracts)
        atoms = [{"op": "in", "field": "payload.x", "value": [False, 0]},
                 {"op": "eq", "field": "payload.x", "value": 0}]
        self.assertEqual(candidate(atoms), [{"tool": "custom", "exact_arguments": {"x": 0}}])
        self.assertIs(type(candidate(atoms)[0]["exact_arguments"]["x"]), int)
        self.assertEqual(candidate([{"op": "in", "field": "payload." + k, "value": list(range(5))}
                                    for k in ("x", "y")]), [])

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
