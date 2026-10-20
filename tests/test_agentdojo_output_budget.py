import unittest
from tests.test_agentdojo_pi import FixtureMixin, PI
from tests import test_agentdojo_pi as fixtures
from adapters.agentdojo_pi.errors import ActionModelError


@unittest.skipUnless(PI.exists(), "Installed pi SDK required")
class OutputBudgetTests(FixtureMixin, unittest.TestCase):
    smoke = fixtures.PiSmokeTests.smoke

    def test_http_200_missing_finish_at_budget_floor_is_task_local(self):
        with self.assertRaises(ActionModelError) as caught:
            self.smoke("baseline", tool="get_current_day", context_window=16384,
                response_usage={"prompt_tokens": 13300, "completion_tokens": 1, "total_tokens": 13301},
                action_output_budget="model", final_finish_reason="missing")
        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic["request"]["http_status"], 200)
        self.assertEqual(diagnostic["status"], "context_limit")
        self.assertTrue(caught.exception.task_local)

    def test_exhausted_context_records_budget_evidence_as_task_local_error(self):
        with self.assertRaises(ActionModelError) as caught:
            self.smoke("baseline", tool="get_current_day", context_window=16384,
                response_usage={"prompt_tokens": 13300, "completion_tokens": 20, "total_tokens": 13320},
                action_output_budget="model", final_finish_reason="length")
        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic["status"], "context_limit")
        self.assertEqual(diagnostic["reason"], "sdk_remaining_output_budget_at_floor")
        self.assertEqual(diagnostic["request"]["sent_max_tokens"], 1)
        self.assertTrue(caught.exception.task_local)

    def test_reproduce_sdk_one_token_limit(self):
        pipe, _, _, requests = self.smoke("baseline", tool="get_current_day", context_window=16384,
            response_usage={"prompt_tokens": 13300, "completion_tokens": 20, "total_tokens": 13320})
        self.assertEqual(pipe.runs[0]["action_requests"][1]["sdk_max_tokens"], 1)
        self.assertEqual(pipe.runs[0]["action_requests"][1]["sent_max_tokens"], 1)
        self.assertEqual(requests[1].get("max_tokens", requests[1].get("max_completion_tokens")), 1)

    def test_model_budget_reaches_wire_without_context_or_message_changes(self):
        pipe, _, _, requests = self.smoke("baseline", tool="get_current_day", context_window=16384,
            response_usage={"prompt_tokens": 13300, "completion_tokens": 20, "total_tokens": 13320},
            action_output_budget="model")
        diagnostic = pipe.runs[0]["action_requests"][1]
        self.assertEqual(diagnostic["sdk_max_tokens"], 1)
        self.assertEqual(diagnostic["sent_max_tokens"], 1)
        self.assertTrue(diagnostic["context_budget_exhausted"])
        self.assertEqual(diagnostic["context_window"], 16384)
        self.assertEqual(diagnostic["http_status"], 200)
        self.assertEqual(requests[1].get("max_tokens", requests[1].get("max_completion_tokens")), 1)
        self.assertEqual(requests[0]["tools"], requests[1]["tools"])
        self.assertTrue(any(m["role"] == "tool" for m in requests[1]["messages"]))

    def test_repeated_execution_error_requests_one_final_answer(self):
        pipe, before, messages, requests = self.smoke("baseline", tool="search_files", stopped=True,
            sequence=[{"query": "fixture-definitely-absent-73482"}, {"query": "fixture-definitely-absent-73482"}])
        self.assertEqual(pipe.runs[0]["stop_reason"], "repeated_tool_error")
        self.assertEqual(pipe.runs[0]["counts"]["tool_errors"], 2)
        self.assertEqual(before, self.env.model_dump())
        self.assertFalse(requests[-1].get("tools"))
        self.assertTrue(pipe.runs[0]["final_answer_received"])


if __name__ == "__main__":
    unittest.main()
