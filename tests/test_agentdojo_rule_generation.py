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
    def test_read_preflight_stays_initial_and_preserves_denies(self):
        import json
        read = [allow({"op": "and", "args": [eq("payload.query", "Networking event"), eq("payload.date", None)]})]
        deny = {"tool": "send_email", "decision": "deny", "predicate": {"op": "true"}}
        with patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
             patch("adapters.agentdojo_pi.pipeline.generate_read_rules", return_value=read) as reader, \
             patch("adapters.agentdojo_pi.pipeline.anchor_rules_llm", return_value=[deny]) as generator, \
             patch("adapters.agentdojo_pi.pipeline.anchor_effect_llm", return_value={}), \
             patch("adapters.agentdojo_pi.pipeline.subprocess.Popen", side_effect=RuntimeError("agent-start")):
            pipeline = self.pipeline()
            pipeline.read_preflight = True
            with self.assertRaisesRegex(RuntimeError, "agent-start"):
                pipeline.query("Find Networking event", self.runtime, self.env)
        first = json.loads(reader.call_args.kwargs["tools_hint"])
        second = json.loads(generator.call_args.kwargs["tools_hint"])
        self.assertEqual(first["generation_scope"], "read_prerequisites")
        self.assertNotIn("send_email", [t["name"] for t in first["tools"]])
        self.assertNotIn("reschedule_calendar_event", [t["name"] for t in first["tools"]])
        self.assertEqual(second["initial_read_rules"], read)
        self.assertEqual(generator.call_args_list[0].args[0], "Find Networking event")
        evidence = json.loads(next(pipeline.output.glob("policy-*.json")).read_text())
        self.assertIn(deny, evidence["rules"])
        self.assertTrue(evidence["read_preflight"])
        self.assertEqual([r["stage"] for r in pipeline.intent_requests], ["read_rules", "rules", "effects"])

    def test_read_preflight_cannot_smuggle_write_or_wildcard_rules(self):
        from policy.intent_output import IntentStageError
        for tool in ("send_email", "*"):
            proposed = [{"tool": tool, "decision": "allow", "predicate": {"op": "true"}}]
            with self.subTest(tool=tool), \
                 patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
                 patch("adapters.agentdojo_pi.pipeline.generate_read_rules", return_value=proposed) as generator, \
                 patch("adapters.agentdojo_pi.pipeline.subprocess.Popen") as proc:
                pipeline = self.pipeline()
                pipeline.read_preflight = True
                with self.assertRaises(IntentStageError):
                    pipeline.query("Find an event", self.runtime, self.env)
                self.assertEqual(generator.call_count, 1)
                proc.assert_not_called()

    def test_unrelated_invalid_allow_cannot_poison_valid_read_or_remove_deny(self):
        import json
        valid = allow({"op": "and", "args": [eq("payload.query", "Networking event"),
                                                eq("payload.date", "2024-05-26")]})
        invalid = {"tool": "create_file", "decision": "allow", "predicate": eq("payload.filename", 123)}
        deny = {"tool": "send_email", "decision": "deny", "predicate": {"op": "true"}}
        with patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
             patch("adapters.agentdojo_pi.pipeline.anchor_rules_llm", return_value=[valid, invalid, deny]), \
             patch("adapters.agentdojo_pi.pipeline.anchor_effect_llm", return_value={}), \
             patch("adapters.agentdojo_pi.pipeline.subprocess.Popen", side_effect=RuntimeError("agent-start")):
            pipeline = self.pipeline()
            with self.assertRaisesRegex(RuntimeError, "agent-start"):
                pipeline.query("Networking event on May 26th", self.runtime, self.env)
        evidence = json.loads(next(pipeline.output.glob("policy-*.json")).read_text())
        self.assertEqual(evidence["quarantined_allow_rules"][0]["rule"], invalid)
        self.assertIn(deny, evidence["rules"])
        self.assertNotIn(invalid, evidence["rules"])
        self.assertIn("Some initial allow proposals failed validation", evidence["planning_hint"])

    def test_semantic_conflict_stops_before_pi_and_saves_evidence(self):
        import json
        from policy.intent_output import IntentStageError
        bad = [allow(eq("payload.query", "shared")),
               {"tool": "search_calendar_events", "decision": "deny",
                "predicate": eq("payload.query", "shared")}]
        with patch("adapters.agentdojo_pi.pipeline.intent_llm_configured", return_value=True), \
             patch("adapters.agentdojo_pi.pipeline.anchor_rules_llm", return_value=bad), \
             patch("adapters.agentdojo_pi.pipeline.anchor_effect_llm") as effects, \
             patch("adapters.agentdojo_pi.pipeline.subprocess.Popen") as proc:
            pipeline = self.pipeline()
            with self.assertRaises(IntentStageError) as raised:
                pipeline.query("Find shared", self.runtime, self.env)
        self.assertTrue(raised.exception.task_local)
        self.assertEqual(raised.exception.diagnostic["status"], "invalid_rule_semantics")
        evidence = json.loads(next(pipeline.output.glob("intent-rejected-*.json")).read_text())
        self.assertEqual(evidence["rules"], bad)
        effects.assert_not_called()
        proc.assert_not_called()

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
