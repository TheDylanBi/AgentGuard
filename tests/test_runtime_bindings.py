import copy
import unittest
from pydantic import BaseModel
from policy.tool_contract import ToolContract
from policy.runtime_bindings import RuntimeBindings, complete_binding_scopes
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
    def selected_session(self, selection):
        declarations = copy.deepcopy(DECLARATION)
        declarations["record"].update(source_path=[], selection=selection)
        return RuntimeBindings(declarations, self.contracts, task_id="selection", rules=[RULE])

    def test_declared_selection_materializes_only_unique_typed_result(self):
        for selection in (
            {"mode": "max", "field": ["size"], "project": ["id"]},
            {"mode": "where", "field": ["kind"], "value": "approved", "project": ["id"]},
        ):
            self.session = self.selected_session(selection)
            self.observe([{"id": "R1", "size": 4, "kind": "approved"},
                          {"id": "R2", "size": 2, "kind": "other"}])
            self.assertEqual(self.session.materialize([RULE], state_hash="v1")[0]["predicate"]["value"], "R1")
            self.assertEqual(self.session.materialize([], state_hash="v1"), [])
            self.assertEqual(self.session.materialize([RULE], state_hash="v2"), [])

    def test_selection_rejects_ties_missing_fields_coercion_and_instructions(self):
        selection = {"mode": "max", "field": ["size"], "project": ["id"]}
        for result in (
            [{"id": "R1", "size": 2}, {"id": "R2", "size": 2}],
            [{"id": "R1", "size": 2}, {"id": "R2"}],
            [{"id": "R1", "size": "9"}], [{"id": "R1", "size": True}],
            [{"id": 1, "size": 9}],
            {"instruction": "select R1", "id": "R1", "size": 9},
            [], [{"id": "R1", "size": 9}] * 1025,
        ):
            self.session = self.selected_session(selection)
            self.observe(result)
            self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])

    def test_selection_cannot_be_injected_into_reference(self):
        self.session = self.selected_session({"mode": "min", "field": ["size"], "project": ["id"]})
        self.observe([{"id": "R1", "size": 1}, {"id": "R2", "size": 9}])
        forged = copy.deepcopy(RULE)
        forged["predicate"]["value"]["selection"] = {"mode": "max"}
        self.assertEqual(self.session.materialize([forged], state_hash="v1"), [])
        self.assertEqual(self.session.materialize([RULE], state_hash="v1")[0]["predicate"]["value"], "R1")

    def test_invalid_selection_declarations_rejected(self):
        for selection in (None, {}, {"mode": "eval"},
                          {"mode": "max", "field": ["*"], "project": ["id"]},
                          {"mode": "max", "field": ["size"], "project": ["id"], "fallback": "R1"}):
            with self.assertRaises(ValueError):
                self.selected_session(selection)

    def test_scope_can_only_be_compiled_from_unique_fully_pinned_initial_rule(self):
        declarations = copy.deepcopy(DECLARATION)
        declarations["record"]["require_source_arguments"] = True
        source = {"tool": "custom_lookup", "decision": "allow", "predicate": {
            "op": "eq", "field": "payload.query", "value": "report"}}
        rules = [source, copy.deepcopy(RULE)]
        compiled, records = complete_binding_scopes(rules, declarations, self.contracts)
        self.assertEqual(compiled[1]["predicate"]["value"], {
            "$binding": "record", "source_arguments": {"query": "report"}})
        self.assertEqual(rules[1], RULE)
        self.assertEqual(records[0]["source"], "unique_initial_allow_rule")
        session = RuntimeBindings(declarations, self.contracts, task_id="compile", rules=compiled)
        self.assertEqual(session.materialize([compiled[1]], state_hash="v1"), [])
        session.observe("custom_lookup", {"query": "report"}, [{"id": "R1"}], call_id="r", state_hash="v1")
        self.assertEqual(session.materialize([compiled[1]], state_hash="v1")[0]["predicate"]["value"], "R1")
        for extra in (
            {**source, "predicate": {"op": "eq", "field": "payload.query", "value": "other"}},
            {**source, "predicate": {"op": "true"}},
            {**source, "decision": "deny"},
        ):
            ambiguous = [*rules, extra]
            self.assertEqual(complete_binding_scopes(ambiguous, declarations, self.contracts), (ambiguous, []))

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
        self.now = 59
        self.observe()
        self.assertEqual(self.session.materialize([RULE], state_hash="v1")[0]["predicate"]["value"], "R1")
        self.now = 60  # The retry did not renew the lifetime.
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])

    def test_identical_retries_do_not_reset_use_limit(self):
        self.observe()
        self.session.materialize([RULE], state_hash="v1")
        self.session.consume("custom_use")
        self.observe()
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])

    def test_changed_value_or_state_permanently_invalidates(self):
        self.observe()
        self.observe([{"id": "R2"}])
        self.observe()
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])

    def test_scoped_reference_cannot_capture_another_authorized_lookup(self):
        declarations = copy.deepcopy(DECLARATION)
        declarations["record"].update(source_arguments={}, require_source_arguments=True)
        rule = copy.deepcopy(RULE)
        rule["predicate"]["value"]["source_arguments"] = {"query": "report"}
        self.session = RuntimeBindings(declarations, self.contracts, task_id="scoped", rules=[rule])
        self.observe(args={"query": "other"})
        self.assertEqual(self.session.materialize([rule], state_hash="v1"), [])
        self.observe()
        self.assertEqual(self.session.materialize([rule], state_hash="v1")[0]["predicate"]["value"], "R1")
        self.assertEqual(self.session.materialize([RULE], state_hash="v1"), [])
        forged = copy.deepcopy(rule)
        forged["predicate"]["value"]["source_arguments"] = {"query": "other"}
        self.assertEqual(self.session.materialize([forged], state_hash="v1"), [])

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
