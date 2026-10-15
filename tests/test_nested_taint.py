import unittest
from types import SimpleNamespace
from policy import taint


class NestedTaintTests(unittest.TestCase):
    caps = {"network_egress": "allowed"}
    state = {"dirty": True, "tainted_objects": [{"object_id": "/private/a", "source": "private_file"}]}

    def action(self, payload):
        return SimpleNamespace(type="send", target="recipient", payload=payload)

    def verdict(self, payload):
        return taint.classify(self.action(payload), self.caps, self.state)[0]

    def test_nested_dictionary_and_array_match_top_level(self):
        for payload in ({"file": "/private/a"}, {"attachments": [{"file": "/private/a"}]},
                        {"batch": [[{"body": {"resource": "/private/a/child"}}]]}):
            self.assertEqual(self.verdict(payload), "BLOCK")

    def test_all_elements_are_scanned(self):
        self.assertEqual(self.verdict({"files": [None, 3, False, {}, [], "/private/a"]}), "BLOCK")

    def test_field_paths_are_precise(self):
        hits = taint.references_tainted_field_level(self.action({"attachments": [{"file": "/private/a"}]}), self.state["tainted_objects"])
        self.assertEqual(hits, [("payload.attachments[0].file", "/private/a")])
        hits = taint.references_tainted_field_level(self.action({"a.b": ["/private/a"]}), self.state["tainted_objects"])
        self.assertEqual(hits[0][0], 'payload["a.b"][0]')

    def test_substring_and_embedded_text_remain_uncertain(self):
        for value in ("/private/abc", "summary of /private/a", '{"file":"/private/a"}'):
            self.assertEqual(self.verdict({"nested": [value]}), "CONFIRM")

    def test_keys_are_not_treated_as_reference_values(self):
        self.assertEqual(self.verdict({"/private/a": "description"}), "CONFIRM")

    def test_clean_and_non_sink_behavior_unchanged(self):
        a = self.action({"attachments": [{"file": "/private/a"}]})
        self.assertIsNone(taint.classify(a, {}, self.state))
        self.assertIsNone(taint.classify(a, self.caps, {"dirty": False, "tainted_objects": []}))

    def test_cycle_and_scan_limits_cannot_degrade_to_confirm(self):
        cycle = {}; cycle["self"] = cycle
        deep = {}; cursor = deep
        for _ in range(taint.MAX_SCAN_DEPTH + 1):
            cursor["next"] = {}; cursor = cursor["next"]
        for payload in (cycle, deep, {"items": [0] * taint.MAX_SCAN_NODES}, {"obj": object()}, {"x": float("nan")}):
            self.assertEqual(self.verdict(payload), "BLOCK")

    def test_shared_acyclic_container_is_not_a_cycle(self):
        shared = {"text": "ordinary"}
        self.assertEqual(self.verdict({"a": shared, "b": shared}), "CONFIRM")


if __name__ == "__main__":
    unittest.main()
