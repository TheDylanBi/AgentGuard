import copy
import unittest
from unittest.mock import patch
from tests.test_agentdojo_pi import FixtureMixin, MANIFEST, PI, NODE
from adapters.agentdojo_pi.pipeline import PiPipeline


def eq(field, value):
    return {"op": "eq", "field": field, "value": value}


def allow(pred):
    return {"tool": "search_calendar_events", "decision": "allow", "predicate": pred}


class RuleGenerationTests(FixtureMixin, unittest.TestCase):
    def pipeline(self):
        return PiPipeline(manifest=MANIFEST, pi_package=PI, pi_agent_dir=self.root,
            provider="fixture", model="fixture", mode="guarded", output=self.root / "output",
            node=NODE, trusted_current_day="2024-05-15")

    def test_bad_fields_repaired_once_before_agent_start(self):
        bad = [allow(eq("query", "Networking event")), allow(eq("date", "2024-05-26"))]
        good = [allow({"op": "and", "args": [eq("payload.query", "Networking event"),
                                               eq("payload.date", "2024-05-26")]})]
        with patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
             patch("adapters.agentdojo_pi.pipeline.anchor_rules_llm", side_effect=[bad, good]) as rules, \
             patch("adapters.agentdojo_pi.pipeline.anchor_effect_llm", return_value={}), \
             patch("adapters.agentdojo_pi.pipeline.subprocess.Popen", side_effect=RuntimeError("agent-start")):
            with self.assertRaisesRegex(RuntimeError, "agent-start"):
                self.pipeline().query("Networking event on May 26th", self.runtime, self.env)
        self.assertEqual(rules.call_count, 2)
        feedback = rules.call_args.kwargs["validation_feedback"]
        self.assertEqual(feedback["errors"][0]["code"], "unknown_field_path")
        self.assertEqual(feedback["previous_rules"], bad)

    def test_failed_or_broadened_repair_never_starts_agent(self):
        bad = [allow(eq("query", "Networking event"))]
        for replacement in (bad, [allow(eq("payload.query", "different event"))]):
            with self.subTest(replacement=replacement), \
                 patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
                 patch("adapters.agentdojo_pi.pipeline.anchor_rules_llm", side_effect=[copy.deepcopy(bad), replacement]) as rules, \
                 patch("adapters.agentdojo_pi.pipeline.anchor_effect_llm") as effects, \
                 patch("adapters.agentdojo_pi.pipeline.subprocess.Popen") as proc:
                pipeline = self.pipeline()
                with self.assertRaisesRegex(RuntimeError, "invalid_rule_schema"):
                    pipeline.query("Task", self.runtime, self.env)
                self.assertEqual(rules.call_count, 2)
                self.assertEqual(pipeline.runs, [])
                effects.assert_not_called()
                proc.assert_not_called()

    def test_malformed_deny_is_not_retried_or_discarded(self):
        bad = [{"tool": "search_calendar_events", "decision": "deny", "predicate": eq("query", "private")}]
        with patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
             patch("adapters.agentdojo_pi.pipeline.anchor_rules_llm", return_value=bad) as rules, \
             patch("adapters.agentdojo_pi.pipeline.subprocess.Popen") as proc:
            with self.assertRaisesRegex(RuntimeError, "invalid_rule_schema"):
                self.pipeline().query("Task", self.runtime, self.env)
        self.assertEqual(rules.call_count, 1)
        proc.assert_not_called()

    def test_syntax_failure_regenerates_once_from_original_task(self):
        from policy.intent_anchor import anchor_rules_llm
        with patch("policy.intent_anchor._chat", side_effect=['{"rules":broken}', '{"rules":[]}']) as chat:
            pipeline = self.pipeline()
            self.assertEqual(pipeline._intent_call("rules", anchor_rules_llm, "trusted original task"), [])
        self.assertEqual(chat.call_count, 2)
        self.assertIn("trusted original task", chat.call_args.args[1])
        self.assertNotIn('{"rules":broken}', chat.call_args.args[1])
        self.assertEqual(len(pipeline.intent_requests), 2)
        self.assertIsNone(pipeline.last_intent_diagnostic)

    def test_syntax_and_schema_share_two_request_budget(self):
        import json
        from policy.intent_output import IntentStageError
        bad = {"rules": [allow(eq("query", "Networking event"))]}
        with patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
             patch("policy.intent_anchor._chat", side_effect=['broken', json.dumps(bad)]) as chat, \
             patch("adapters.agentdojo_pi.pipeline.subprocess.Popen") as proc:
            with self.assertRaises(IntentStageError):
                self.pipeline().query("Networking event on May 26th", self.runtime, self.env)
        self.assertEqual(chat.call_count, 2)
        proc.assert_not_called()

    def test_invalid_deny_clause_is_not_regenerated(self):
        import json
        from policy.intent_anchor import anchor_rules_llm
        from policy.intent_output import IntentStageError
        bad = {"rules": [{"tool":"search_calendar_events","decision":"deny","predicate":{"op":"bad"}}]}
        with patch("policy.intent_anchor._chat", return_value=json.dumps(bad)) as chat:
            with self.assertRaises(IntentStageError):
                self.pipeline()._intent_call("rules", anchor_rules_llm, "task")
        self.assertEqual(chat.call_count, 1)
