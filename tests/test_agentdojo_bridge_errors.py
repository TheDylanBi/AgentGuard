import unittest
from tests.test_agentdojo_pi import PiSmokeTests, PI
from adapters.agentdojo_pi.errors import ActionModelError


@unittest.skipUnless(PI.exists(), "Installed pi SDK required")
class BridgeErrorTests(PiSmokeTests):
    # Inherit the real SDK HTTP fixture; existing smoke tests also guard against
    # regression in host checks, finalization and normalization.
    def test_unknown_tool_has_result_and_model_can_answer(self):
        pipe, before, messages, requests = self.smoke("baseline", tool="calculate_time_difference",
            args={"start_time": "11:00", "end_time": "12:30"})
        self.assertEqual(pipe.runs[0]["sdk_rejections"], 1)
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 0)
        self.assertEqual(before, self.env.model_dump())
        self.assertEqual(messages[2]["error"], "sdk_preexecution_rejection")
        self.assertIn("not found", str(requests[1]["messages"]))

    def test_sdk_invalid_arguments_never_execute(self):
        pipe, before, messages, _ = self.smoke("baseline", tool="get_day_calendar_events", args={})
        self.assertEqual(pipe.runs[0]["sdk_rejections"], 1)
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 0)
        self.assertEqual(before, self.env.model_dump())

    def test_unknown_tool_then_valid_call_still_requires_guard_authorization(self):
        pipe, _, messages, _ = self.smoke("guarded", tool="invented_tool", rules=[{
            "tool": "get_current_day", "decision": "allow", "predicate": {"op": "true"}}],
            steps=[{"tool": "invented_tool", "arguments": {}},
                   {"tool": "get_current_day", "arguments": {}}])
        self.assertEqual(pipe.runs[0]["sdk_rejections"], 1)
        self.assertEqual(pipe.runs[0]["counts"]["executed"], 1)
        self.assertEqual(len([m for m in messages if m["role"] == "tool"]), 2)

    def test_repeated_sdk_rejections_are_bounded(self):
        with self.assertRaises(ActionModelError) as caught:
            self.smoke("baseline", tool="invented_tool", sequence=[{}, {}, {}])
        self.assertEqual(caught.exception.diagnostic["status"], "tool_rejection_budget_exhausted")

    def test_truncated_proposal_does_not_execute(self):
        with self.assertRaises(ActionModelError) as caught:
            self.smoke("baseline", tool="create_file", args={"filename": "never.txt", "content": "never"},
                       finish_reason="length")
        self.assertEqual(caught.exception.diagnostic["status"], "truncated_output")

    def test_reasoning_only_is_not_an_answer_even_with_stop(self):
        with self.assertRaises(ActionModelError) as caught:
            self.smoke("baseline", response_text="<think>Still planning.</think>")
        self.assertEqual(caught.exception.diagnostic["status"], "missing_final_answer")

    def test_qwen_off_is_in_actual_http_request(self):
        _, _, _, requests = self.smoke("baseline", tool="get_current_day", reasoning=True,
                                       thinking_format="qwen-chat-template")
        self.assertTrue(all(r["chat_template_kwargs"]["enable_thinking"] is False for r in requests))


if __name__ == "__main__":
    unittest.main()
