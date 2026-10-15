import copy
import unittest
from pydantic import BaseModel
from policy.tool_contract import ToolContract
from policy.runtime_bindings import RuntimeBindings
from policy.context_bindings import bind_dates


class Lookup(BaseModel):
    query: str


class Use(BaseModel):
    record_id: str


DECLARATION = {"record": {"source_tool": "custom_lookup", "source_path": ["*", "id"],
    "source_arguments": {"query": "report"}, "target_tool": "custom_use", "target_field": "record_id",
    "ttl_seconds": 60, "max_uses": 1, "reason": "Reviewed identifier from a unique authorized lookup."}}
RULE = {"tool": "custom_use", "decision": "allow", "predicate": {
    "op": "eq", "field": "payload.record_id", "value": {"$binding": "record"}}}


class RuntimeBindingTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.contracts = {"custom_lookup": ToolContract("custom_lookup", Lookup),
                          "custom_use": ToolContract("custom_use", Use)}
        self.session = self.new_session()

    def new_session(self):
        return RuntimeBindings(DECLARATION, self.contracts, task_id="task", clock=lambda: self.now)

    def observe(self, result=None, args=None):
        self.session.observe("custom_lookup", args or {"query": "report"},
            [{"id": "R1"}] if result is None else result, call_id="lookup1", state_hash="v1")

    def test_only_explicit_template_materializes_and_consumes(self):
        original = copy.deepcopy(RULE)
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])
        self.observe()
        self.assertEqual(self.session.materialize([], state_hash="v1"), [])
        rules = self.session.materialize([RULE], state_hash="v1")
        self.assertEqual(rules[0]["predicate"]["value"], "R1")
        self.assertEqual(RULE, original)
        self.session.consume("custom_use")
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])

    def test_stale_expired_and_cross_task_values_never_bind(self):
        self.observe()
        self.assertEqual(self.session.materialize([RULE], state_hash="v2"), [])
        self.assertEqual(self.new_session().materialize([RULE], state_hash="v1"), [])
        self.now = 60
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])

    def test_ambiguous_missing_and_wrong_type_values_fail_closed(self):
        for result in ([], [{"id": "R1"}, {"id": "R2"}], [{"id": "R1"}, {"id": "R1"}],
                       [{"name": "R1"}], [{"id": 1}]):
            self.session = self.new_session()
            self.observe(result)
            self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])

    def test_wrong_source_arguments_and_repeated_queries_do_not_refresh(self):
        self.observe(args={"query": "another"})
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])
        self.observe()
        self.observe()
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])

    def test_cannot_retarget_binding_or_use_under_negation(self):
        self.observe()
        for rule in ({**RULE, "tool": "other"}, {**RULE, "predicate": {"op": "not", "args": [RULE["predicate"]]}},
                     {**RULE, "predicate": {**RULE["predicate"], "field": "payload.query"}}):
            self.assertEqual(self.session.materialize([rule], state_hash="v1"), [])

    def test_explicit_deny_is_preserved(self):
        deny = {"tool": "custom_use", "decision": "deny", "predicate": {"op": "true"}}
        self.observe()
        self.assertEqual(self.session.materialize([RULE, deny], state_hash="v1")[1], deny)

    def test_bad_declarations_rejected(self):
        for key, value in (("ttl_seconds", 0), ("max_uses", True), ("target_tool", "unknown"),
                           ("target_field", "unknown"), ("source_path", [0]), ("reason", "")):
            declarations = copy.deepcopy(DECLARATION)
            declarations["record"][key] = value
            with self.assertRaises(ValueError):
                RuntimeBindings(declarations, self.contracts, task_id="task")

    def test_context_binding_accepts_new_tool_by_declaration(self):
        rules = [{"tool": "new_report_tool", "decision": "allow", "predicate": {"op": "true"}}]
        updated, records = bind_dates(rules, "Read report on May 26", "2024-05-15",
            {"new_report_tool": {"report_day": {"kind": "user_date"}}})
        self.assertEqual(updated[0]["predicate"]["args"][1],
                         {"op": "eq", "field": "payload.report_day", "value": "2024-05-26"})
        self.assertEqual(len(records), 1)
