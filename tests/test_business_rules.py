import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from policy.business_rules import BusinessPolicy
from policy.engine import PolicyEngine


class BusinessRulesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "business.json"
        self.action = SimpleNamespace(type="send", target="user", payload={"to": "allowed", "amount": 10})

    def policy(self, rules):
        self.path.write_text(json.dumps({"version": 1, "rules": rules}), encoding="utf-8")
        return BusinessPolicy(self.path)

    def test_empty_default_does_not_add_prohibitions(self):
        self.assertIsNone(BusinessPolicy().check(self.action))

    def test_exact_action_and_global_deny(self):
        p = self.policy([{"id": "no-send", "actions": ["send"], "mode": "deny"}])
        self.assertEqual(p.check(self.action)["rule"], "business.no-send")
        self.action.type = "read"
        self.assertIsNone(p.check(self.action))
        self.assertEqual(self.policy([{"id": "pause", "actions": ["*"], "mode": "deny"}]).check(self.action)["verdict"], "BLOCK")

    def test_require_rules_are_intersected_not_first_match_allow(self):
        rules = [{"id": "recipient", "actions": ["send"], "mode": "require",
                  "parameter_constraints": {"to": {"enum": ["allowed"]}}},
                 {"id": "limit", "actions": ["send"], "mode": "require",
                  "parameter_constraints": {"amount": {"maximum": 5}}}]
        self.assertEqual(self.policy(rules).check(self.action)["rule"], "business.limit")

    def test_does_not_grant_access_or_depend_on_intent(self):
        self.policy([{"id": "no-send", "actions": ["send"], "mode": "deny"}])
        engine = PolicyEngine("policy/policies", self.path)
        for enabled in (True, False):
            r = engine.evaluate(self.action, "unknown", 0, capability={"actions": ["send"]},
                rules=[{"tool": "send", "decision": "allow", "predicate": {"op": "true"}}], enable_rules=enabled)
            self.assertEqual(r["rule"], "business.no-send")
        self.policy([])
        self.assertEqual(PolicyEngine("policy/policies", self.path).evaluate(self.action, "unknown", 0)["verdict"], "BLOCK")

    def test_loaded_policy_is_snapshot_until_restart(self):
        p = self.policy([{"id": "stop", "actions": ["*"], "mode": "deny"}])
        h = p.fingerprint
        self.policy([])
        self.assertIsNotNone(p.check(self.action))
        self.assertEqual(h, p.fingerprint)
        self.assertNotEqual(h, BusinessPolicy(self.path).fingerprint)

    def test_invalid_configuration_never_silently_disables_rules(self):
        for data in ({"version": True, "rules": []}, {"version": 2, "rules": []},
                     {"version": 1, "rules": [{"id": "x", "actions": ["send"], "mode": "allow"}]},
                     {"version": 1, "rules": [{"id": "x", "actions": ["send*"], "mode": "deny"}]},
                     {"version": 1, "rules": [{"id": "x", "actions": ["send"], "mode": "require", "parameter_constraints": {}}]},
                     {"version": 1, "rules": [{"id": "x", "actions": ["send"], "mode": "deny", "parameter_constraints": {}}]}):
            with self.subTest(data=data):
                self.path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    BusinessPolicy(self.path)
        self.path.write_text('{"version":1,"rules":[],"rules":[]}', encoding="utf-8")
        with self.assertRaises(ValueError):
            BusinessPolicy(self.path)
        with self.assertRaises(FileNotFoundError):
            BusinessPolicy(self.path.with_name("missing.json"))


if __name__ == "__main__":
    unittest.main()
