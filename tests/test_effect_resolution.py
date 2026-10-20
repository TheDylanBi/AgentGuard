import copy
import unittest

from policy.behavior import extract_actual_effect
from policy.behavior_alignment import check_behavior_alignment
from policy.effect_model import ExpectedEffect
from tests.test_agentdojo_pi import FixtureMixin


def rule(tool, values, decision="allow"):
    return {"tool": tool, "decision": decision, "predicate": {"op": "and", "args": [
        {"op": "eq", "field": "payload." + k, "value": v} for k, v in values.items()]}}


class RecipientTests(unittest.TestCase):
    def test_argument_origin_contract_requires_exact_reviewed_coverage(self):
        from adapters.agentdojo_pi.effect_resolution import validate_effect_declarations
        valid = {"schema_hash": "pinned", "dataflow_mode": "declared_arguments", "dataflow_fields": {
            "destination": {"origin": "initial", "reason": "User-selected target"},
            "content": {"origin": "binding", "bindings": ["reviewed_source"], "reason": "Authorized copy"}}}
        validate_effect_declarations(valid, {"destination", "content"})
        for bad in ({**valid, "schema_hash": None}, {**valid, "dataflow_fields": {}},
                    {**valid, "dataflow_mode": "initial_arguments"},
                    {**valid, "dataflow_fields": {**valid["dataflow_fields"], "extra": {}}}):
            with self.assertRaises(ValueError):
                validate_effect_declarations(bad, {"destination", "content"})

    def test_object_id_is_not_a_recipient_and_unresolved_effect_fails_closed(self):
        caps = {"target_type": "object", "effect_type": "external_communication", "external_share": "allowed"}
        actual = extract_actual_effect("update", "5", {"id": "5"}, caps)
        self.assertEqual(actual.recipients, [])
        result = check_behavior_alignment(ExpectedEffect(tool="update"), actual, caps)
        self.assertIn("unresolved_recipients", result["violations"])
        actual = extract_actual_effect("update", "5", {"id": "5"}, caps,
                                       resolved_recipients=["outside@example.test"])
        result = check_behavior_alignment(ExpectedEffect(tool="update", allowed_recipients=["allowed@example.test"]), actual, caps)
        self.assertIn("recipient_out_of_scope", result["violations"])

    def test_path_is_checked_as_target_not_as_email(self):
        caps = {"target_type": "path", "effect_type": "filesystem_write", "persistence": "allowed"}
        actual = extract_actual_effect("write", "/allowed", {}, caps)
        expected = ExpectedEffect(tool="write", allowed_targets=["/allowed"], allowed_recipients=["a@example.test"])
        self.assertTrue(check_behavior_alignment(expected, actual, caps)["aligned"])
        expected.allowed_targets = ["/different"]
        self.assertIn("target_out_of_scope", check_behavior_alignment(expected, actual, caps)["violations"])


class ResolvedHostTests(FixtureMixin, unittest.TestCase):
    def test_user_literal_compilation_executes_exact_text_without_touching_other_arguments(self):
        from policy.text_constraints import user_text_literals, bind_user_text
        query = 'Create with description Discuss milestones..'
        values = {"title": "Review", "description": "Discuss milestones", "start_time": "2024-05-20 12:00",
                  "end_time": "2024-05-20 13:00", "participants": [], "location": None}
        declarations = {name: spec.get("text_constraints", {}) for name, spec in self.manifest["tools"].items()}
        rules, records = bind_user_text([rule("create_calendar_event", values)], user_text_literals(query, declarations))
        host = self.host(rules=rules, effect_profile={})
        before = copy.deepcopy(self.env.model_dump())
        self.assertIsNotNone(host.call("missing-period", "create_calendar_event", values)[1])
        self.assertEqual(before, self.env.model_dump())
        self.assertIsNone(host.call("corrected-text", "create_calendar_event",
                                   {**values, "description": "Discuss milestones."})[1])
        self.assertTrue(records[0]["terminal_punctuation_restored"])
        self.assertEqual(host.counts["executed"], 1)
        created = [event for key, event in self.env.calendar.events.items() if key not in before["calendar"]["events"]]
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].description, "Discuss milestones.")

    def test_wrong_resource_title_can_recover_via_authorized_lookup(self):
        host = self.host(rules=self.calendar_rules(), effect_profile={})
        before = copy.deepcopy(self.env.model_dump())
        self.assertIsNotNone(host.call("early", "reschedule_calendar_event", {
            "event_id": "Fixture selected event", "new_start_time": "2024-05-20 10:00", "new_end_time": None})[1])
        self.assertEqual(before, self.env.model_dump())
        self.assertEqual(host.last_feedback["issue"], "binding_prerequisite")
        self.assertFalse(host.last_feedback["stop_task"])
        event_id = self.read(host)
        self.assertIsNone(host.call("corrected", "reschedule_calendar_event", {
            "event_id": event_id, "new_start_time": "2024-05-20 10:00", "new_end_time": None})[1])
        self.assertEqual(host.counts["executed"], 2)

    def setUp(self):
        super().setUp()
        next(iter(self.env.calendar.events.values())).title = "Fixture selected event"

    def calendar_rules(self):
        query = {"query": "Fixture selected event", "date": None}
        values = {"event_id": {"$binding": "selected_event_reschedule", "source_arguments": query},
                  "new_start_time": "2024-05-20 10:00", "new_end_time": None}
        return [rule("search_calendar_events", query), rule("reschedule_calendar_event", values)]

    def read(self, host):
        result, error = host.call("read", "search_calendar_events", {"query": "Fixture selected event", "date": None})
        self.assertIsNone(error)
        self.assertEqual(len(result), 1)
        return result[0].id_

    def test_bound_resource_update_uses_real_audience_and_keeps_session_taint(self):
        host = self.host(rules=self.calendar_rules(), effect_profile={})
        event_id = self.read(host)
        _, error = host.call("update", "reschedule_calendar_event", {
            "event_id": event_id, "new_start_time": "2024-05-20 10:00", "new_end_time": None})
        self.assertIsNone(error)
        self.assertTrue(host.taint["dirty"])
        entry = host.audit.get("update:start")
        self.assertEqual(entry["argument_proof"]["kind"], "bound_resource_update")
        self.assertIn("recipients_hash", entry["effect_resolution"])
        self.assertEqual(host.counts["executed"], 2)

    def test_resolved_audience_still_respects_explicit_restrictions(self):
        host = self.host(rules=self.calendar_rules(), effect_profile={"allowed_recipients": ["nobody@example.test"]})
        event_id = self.read(host)
        before = copy.deepcopy(self.env.model_dump())
        _, error = host.call("update", "reschedule_calendar_event", {
            "event_id": event_id, "new_start_time": "2024-05-20 10:00", "new_end_time": None})
        self.assertIn("recipient_out_of_scope", error)
        self.assertEqual(before, self.env.model_dump())

    def test_stale_or_wrong_binding_never_gets_a_dataflow_proof(self):
        host = self.host(rules=self.calendar_rules(), effect_profile={})
        event_id = self.read(host)
        self.env.calendar.events[event_id].participants.append("changed@example.test")
        before = copy.deepcopy(self.env.model_dump())
        self.assertIsNotNone(host.call("update", "reschedule_calendar_event", {
            "event_id": event_id, "new_start_time": "2024-05-20 10:00", "new_end_time": None})[1])
        self.assertEqual(before, self.env.model_dump())

    def test_initial_argument_proof_does_not_waive_direct_taint_or_explicit_deny(self):
        values = {"title": "Fixed", "description": "fixed text", "start_time": "2024-05-20 12:00",
                  "end_time": "2024-05-20 13:00", "participants": [], "location": None}
        allow = rule("create_calendar_event", values)
        for direct, deny in ((True, False), (False, True), (False, False)):
            with self.subTest(direct=direct, deny=deny):
                host = self.host(rules=[allow] + ([rule("create_calendar_event", values, "deny")] if deny else []),
                                 effect_profile={})
                host.taint.update(dirty=True, tainted_objects=[{"object_id": "fixed text" if direct else "other source"}])
                before = copy.deepcopy(self.env.model_dump())
                _, error = host.call("create" + str(direct) + str(deny), "create_calendar_event", values)
                if direct or deny:
                    self.assertIsNotNone(error)
                    self.assertEqual(before, self.env.model_dump())
                else:
                    self.assertIsNone(error)
                self.assertTrue(host.taint["dirty"])


if __name__ == "__main__":
    unittest.main()
