import copy
import unittest
from pydantic import BaseModel
from policy.text_constraints import user_text_literals, bind_user_text, validate_text_declarations
from policy.intent_validation import rule_semantic_errors
from policy.tool_contract import ToolContract
from attestation.hashing import object_hash


DECLARATIONS = {"publish_note": {"text": {"markers": ["with description"], "reason": "Reviewed text field"}}}


class Parameters(BaseModel):
    text: str
    destination: str


def rule(value, decision="allow"):
    return {"tool": "publish_note", "decision": decision, "predicate": {"op": "and", "args": [
        {"op": "eq", "field": "payload.text", "value": value},
        {"op": "eq", "field": "payload.destination", "value": "original"}]}}


class TextConstraintTests(unittest.TestCase):
    def test_exact_spans_retain_case_spaces_and_punctuation(self):
        for text, expected in [('Create with description Review the draft.. Next instruction.', 'Review the draft.'),
                               ('Create with description " Keep THIS! ".', ' Keep THIS! '),
                               ("Create with description '你好。'.", '你好。')]:
            literals = user_text_literals(text, DECLARATIONS)
            self.assertEqual(len(literals), 1)
            self.assertEqual(literals[0]["value"], expected)
            self.assertEqual(text[literals[0]["start"]:literals[0]["end"]], expected)

    def test_ambiguous_or_unrecognized_text_is_not_guessed(self):
        for text in ['Create with description Hello.', 'Create with description Wait...',
                     'Create with description "unterminated', 'Do not create with description Hi..',
                     'Create with description A.. and with description B..',
                     'Create with description First sentence. Second sentence..']:
            self.assertEqual(user_text_literals(text, DECLARATIONS), [], text)

    def test_only_missing_terminal_punctuation_is_restored_and_denies_survive(self):
        original = [rule('Review draft')]
        saved = copy.deepcopy(original)
        literals = user_text_literals('Create with description Review draft..', DECLARATIONS)
        compiled, records = bind_user_text(original, literals)
        self.assertEqual(original, saved)
        self.assertTrue(records[0]['terminal_punctuation_restored'])
        self.assertEqual(compiled[0]['predicate']['args'][0]['args'][1], original[0]['predicate']['args'][1])
        self.assertEqual(bind_user_text([], literals), ([], []))

    def test_punctuation_repair_never_sidesteps_original_deny(self):
        literals = user_text_literals('Create with description Review draft..', DECLARATIONS)
        for value in ('Review draft', 'Review draft.'):
            original = [rule('Review draft'), rule(value, 'deny')]
            compiled, records = bind_user_text(original, literals)
            self.assertFalse(records[0]['terminal_punctuation_restored'])
            self.assertEqual(compiled[1], original[1])
            self.assertEqual(compiled[0]['predicate']['args'][0], original[0]['predicate'])
            errors = rule_semantic_errors(compiled, {'publish_note': ToolContract('publish_note', Parameters)})
            self.assertIn('contradictory_parameter_bounds', {e['code'] for e in errors})

    def test_substantive_changes_and_conflicting_constraints_are_not_rewritten(self):
        literals = user_text_literals('Create with description Review draft..', DECLARATIONS)
        bad = rule('Send credentials')
        conflicting = rule('Review draft')
        conflicting['predicate']['args'].append({'op': 'eq', 'field': 'payload.text', 'value': 'Other'})
        for original in (bad, conflicting):
            compiled, records = bind_user_text([original], literals)
            self.assertFalse(records[0]['terminal_punctuation_restored'])
            self.assertEqual(compiled[0]['predicate']['args'][0], original['predicate'])
            errors = rule_semantic_errors(compiled, {'publish_note': ToolContract('publish_note', Parameters)})
            self.assertIn('contradictory_parameter_bounds', {e['code'] for e in errors})

    def test_declarations_require_known_string_field_and_reviewed_schema(self):
        valid = {'schema_hash': object_hash(Parameters.model_json_schema()),
                 'text_constraints': DECLARATIONS['publish_note']}
        validate_text_declarations(valid, Parameters)
        for invalid in ({'text_constraints': valid['text_constraints']},
                        {**valid, 'text_constraints': {'unknown': valid['text_constraints']['text']}}):
            with self.assertRaises(ValueError):
                validate_text_declarations(invalid, Parameters)


if __name__ == '__main__':
    unittest.main()
