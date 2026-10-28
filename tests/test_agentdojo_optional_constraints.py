import copy
import json
import unittest
from adapters.agentdojo_pi.optional_constraints import complete_rules, validate_empty_values
from tests.test_agentdojo_pi import FixtureMixin


class OptionalConstraintsTests(FixtureMixin, unittest.TestCase):
    email = {"recipients": ["fixture@example.com"], "subject": "Fixture", "body": "Hello"}
    calendar = {"title": "Fixture", "start_time": "2024-05-30 10:20",
                "end_time": "2024-05-30 11:20", "participants": ["fixture@example.com"]}

    def rule(self, tool, args):
        return {"tool": tool, "decision": "allow", "predicate": {"op": "and", "args": [
            {"op": "eq", "field": "payload." + k, "value": v} for k, v in args.items()]}}

    def guarded(self, tool, args, **kwargs):
        return self.host(rules=[self.rule(tool, args)],
                         effect_profile={"allowed_recipients": ["fixture@example.com"]}, **kwargs)

    def test_email_omitted_null_and_empty_lists_execute(self):
        for i, extra in enumerate(({}, {k: None for k in ("cc", "bcc", "attachments")},
                                    {k: [] for k in ("cc", "bcc", "attachments")})):
            with self.subTest(extra=extra):
                host = self.guarded("send_email", self.email)
                _, error = host.call(str(i), "send_email", {**self.email, **extra})
                self.assertIsNone(error)
                self.assertEqual(host.counts["executed"], 1)

    def test_extra_recipient_can_be_removed_without_expanding_authority(self):
        host = self.guarded("send_email", self.email)
        original_rules = copy.deepcopy(host.rules)
        before = self.env.model_dump()
        self.assertIsNotNone(host.call("bad", "send_email", {
            **self.email, "recipients": ["fixture@example.com", "other@example.com"]})[1])
        self.assertEqual(before, self.env.model_dump())
        self.assertTrue(host.last_feedback["retryable"])
        self.assertIsNone(host.call("fixed", "send_email", self.email)[1])
        self.assertEqual(host.counts["executed"], 1)
        self.assertEqual(host.rules, original_rules)

    def test_calendar_omitted_and_empty_optional_values_execute(self):
        for i, extra in enumerate(({}, {"description": "", "location": ""},
                                    {"description": "", "location": None})):
            with self.subTest(extra=extra):
                host = self.guarded("create_calendar_event", self.calendar)
                _, error = host.call(str(i), "create_calendar_event", {**self.calendar, **extra})
                self.assertIsNone(error)
                self.assertEqual(host.counts["executed"], 1)

    def test_nonempty_values_never_inherit_empty_authorization(self):
        cases = [("send_email", self.email, {"cc": ["other@example.com"]}),
                 ("send_email", self.email, {"bcc": ["other@example.com"]}),
                 ("send_email", self.email, {"attachments": [{"type": "file", "file_id": "x"}]}),
                 ("create_calendar_event", self.calendar, {"description": "Added text"}),
                 ("create_calendar_event", self.calendar, {"location": "Office"}),
                 ("create_calendar_event", self.calendar, {"description": " "})]
        for i, (tool, args, extra) in enumerate(cases):
            with self.subTest(extra=extra):
                host = self.guarded(tool, args)
                before = self.env.model_dump()
                self.assertIsNotNone(host.call(str(i), tool, {**args, **extra})[1])
                self.assertEqual(host.counts["executed"], 0)
                self.assertEqual(before, self.env.model_dump())

    def test_invalid_null_string_is_still_rejected(self):
        host = self.guarded("create_calendar_event", self.calendar)
        self.assertIn("Invalid tool arguments", host.call("1", "create_calendar_event", {
            **self.calendar, "description": None})[1])

    def test_explicit_nonempty_and_null_rules_are_preserved(self):
        for i, extra in enumerate(({"description": "Required text", "location": "Office"},
                                    {"description": "", "location": None})):
            args = {**self.calendar, **extra}
            host = self.guarded("create_calendar_event", args)
            self.assertIsNone(host.call(str(i), "create_calendar_event", args)[1])
            self.assertIsNotNone(host.call(str(i) + "other", "create_calendar_event", {
                **args, "description": "Different text"})[1])

    def test_missing_rules_and_missing_required_bounds_are_not_completed(self):
        for i, rules in enumerate(([], [self.rule("send_email", {"subject": "Fixture"})])):
            host = self.host(rules=rules, effect_profile={})
            self.assertIsNotNone(host.call(str(i), "send_email", self.email)[1])
            self.assertEqual(host.counts["executed"], 0)

    def test_existing_deny_business_and_direct_taint_checks_still_win(self):
        rule = self.rule("send_email", self.email)
        deny = {"tool": "send_email", "decision": "deny", "predicate": {"op": "true"}}
        host = self.host(rules=[rule, deny], effect_profile={})
        self.assertIn("ICB-BLOCK", host.call("deny", "send_email", self.email)[1])
        path = self.root / "business.json"
        path.write_text(json.dumps({"version": 1, "rules": [
            {"id": "stop", "actions": ["send_email"], "mode": "deny"}]}))
        host = self.guarded("send_email", self.email, business_policy=path)
        self.assertIn("ICB-BLOCK", host.call("business", "send_email", self.email)[1])
        host = self.guarded("send_email", self.email)
        # Dirty alone permits the existing exact frozen-argument proof. A real
        # tainted object copied into content must still fail that proof's recheck.
        host.taint = {"dirty": True, "tainted_objects": [
            {"object_id":"Hello","source":"external_untrusted"}]}
        self.assertIn("ICB-BLOCK", host.call("taint", "send_email", self.email)[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_completion_is_static_idempotent_and_does_not_change_denies(self):
        rules = [self.rule("send_email", self.email), {"tool": "send_email", "decision": "deny",
                "predicate": {"op": "eq", "field": "payload.cc", "value": None}},
                 {"tool": "*", "decision": "allow", "predicate": {"op": "true"}}]
        original = copy.deepcopy(rules)
        result = complete_rules(rules, self.manifest)
        self.assertEqual(rules, original)
        self.assertEqual(result[1:], original[1:])
        self.assertEqual(result, complete_rules(result, self.manifest))

    def test_capability_and_effect_limits_still_win(self):
        self.manifest["tools"]["send_email"]["capability"]["parameter_constraints"] = {
            "subject": {"enum": ["Only this subject"]}}
        host = self.guarded("send_email", self.email)
        self.assertIn("ICB-BLOCK", host.call("capability", "send_email", self.email)[1])
        del self.manifest["tools"]["send_email"]["capability"]["parameter_constraints"]
        host = self.host(rules=[self.rule("send_email", self.email)],
                         effect_profile={"forbidden_effects": ["external_communication"]})
        self.assertIn("ICB-BLOCK", host.call("effects", "send_email", self.email)[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_partial_or_constraint_is_not_overridden(self):
        rule = self.rule("send_email", self.email)
        rule["predicate"]["args"].append({"op": "or", "args": [
            {"op": "eq", "field": "payload.cc", "value": []}, {"op": "true"}]})
        host = self.host(rules=[rule], effect_profile={})
        self.assertIn("ICB-CONFIRM", host.call("partial", "send_email", self.email)[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_capability_and_effect_limits_still_win(self):
        self.manifest["tools"]["send_email"]["capability"]["parameter_constraints"] = {
            "subject": {"enum": ["Only this subject"]}}
        host = self.guarded("send_email", self.email)
        self.assertIn("ICB-BLOCK", host.call("capability", "send_email", self.email)[1])
        del self.manifest["tools"]["send_email"]["capability"]["parameter_constraints"]
        host = self.host(rules=[self.rule("send_email", self.email)],
                         effect_profile={"forbidden_effects": ["external_communication"]})
        self.assertIn("ICB-BLOCK", host.call("effects", "send_email", self.email)[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_partial_or_constraint_is_not_overridden(self):
        rule = self.rule("send_email", self.email)
        rule["predicate"]["args"].append({"op": "or", "args": [
            {"op": "eq", "field": "payload.cc", "value": []}, {"op": "true"}]})
        host = self.host(rules=[rule], effect_profile={})
        self.assertIn("ICB-CONFIRM", host.call("partial", "send_email", self.email)[1])
        self.assertEqual(host.counts["executed"], 0)

    def test_invalid_empty_declarations_fail_closed(self):
        fields = self.runtime.functions["send_email"].parameters.model_fields
        for value in ({"recipients": [[]]}, {"cc": [["other@example.com"]]}, {"cc": [""]},
                      {"cc": [False]}, {"cc": []}, {"unknown": [None]}, {"cc": [[]]}):
            spec = copy.deepcopy(self.manifest["tools"]["send_email"])
            spec["optional_empty_values"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_empty_values(spec, fields)

    def test_read_tool_unlisted_optional_argument_still_needs_intent_bound(self):
        host = self.host(rules=[self.rule("search_emails", {"query": "meeting"})], effect_profile={})
        _, error = host.call("query", "search_emails", {"query": "meeting"})
        self.assertIn("payload.sender", error)
        self.assertEqual(host.audit.get("query:denied")["rule"], "contract.coverage")
        self.assertEqual(host.counts["executed"], 0)

    def test_manifest_schema_drift_is_rejected_before_execution(self):
        self.manifest["tools"]["send_email"]["schema_hash"] = "obsolete"
        with self.assertRaises(ValueError):
            self.host()

    def test_read_tool_unlisted_optional_argument_still_needs_intent_bound(self):
        host = self.host(rules=[self.rule("search_emails", {"query": "meeting"})], effect_profile={})
        _, error = host.call("query", "search_emails", {"query": "meeting"})
        self.assertIn("payload.sender", error)
        self.assertEqual(host.audit.get("query:denied")["rule"], "contract.coverage")
        self.assertEqual(host.counts["executed"], 0)

    def test_manifest_schema_drift_is_rejected_before_execution(self):
        self.manifest["tools"]["send_email"]["schema_hash"] = "obsolete"
        with self.assertRaises(ValueError):
            self.host()


if __name__ == "__main__":
    unittest.main()
