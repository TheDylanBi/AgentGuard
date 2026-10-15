import unittest
from adapters.agentdojo_pi.feedback import RepairBudget, make_feedback


class FeedbackTests(unittest.TestCase):
    def test_missing_authority_is_not_repairable(self):
        for rule in ("symbolic.underconstrained", "contract.coverage", "p5.taint", "business.deny"):
            self.assertFalse(make_feedback("BLOCK", rule)["retryable"])

    def test_outside_intent_requires_existing_allow(self):
        self.assertFalse(make_feedback("CONFIRM", "symbolic.expansion")["retryable"])
        self.assertTrue(make_feedback("CONFIRM", "symbolic.expansion", has_allow=True)["retryable"])

    def test_only_schema_fields_exposed(self):
        class Contract:
            fields = {"subject": {}}
        result = make_feedback("CONFIRM", "contract.coverage", ["payload.subject", "secret"], Contract())
        self.assertEqual(result["fields"], ["payload.subject"])
        self.assertNotIn("secret", str(result))

    def test_initial_failure_plus_two_revisions(self):
        budget = RepairBudget()
        for i in range(3):
            result = budget.record("tool", {"x": i}, make_feedback("BLOCK", "bridge.arguments"))
            self.assertEqual(result["stop_task"], i == 2)
        self.assertEqual(result["stop_reason"], "repair_budget_exhausted")

    def test_repeated_arguments_ignore_call_id(self):
        budget = RepairBudget()
        budget.record("tool", {"x": 1}, make_feedback("BLOCK", "bridge.arguments"))
        self.assertEqual(budget.before("tool", {"x": 1}), "repeated_rejected_call")

    def test_global_budget_prevents_alternating_tools(self):
        budget = RepairBudget()
        for i in range(6):
            result = budget.record(str(i), {}, make_feedback("BLOCK", "bridge.arguments"))
        self.assertEqual(result["stop_reason"], "repair_budget_exhausted")

    def test_terminal_decision_stays_terminal(self):
        budget = RepairBudget()
        budget.record("tool", {}, make_feedback("BLOCK", "p5.taint"))
        self.assertEqual(budget.before("another_tool", {}), "data_flow_restricted")
