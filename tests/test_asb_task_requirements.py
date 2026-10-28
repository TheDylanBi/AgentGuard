import json
from pathlib import Path
import tempfile
import unittest

from attestation.hashing import object_hash
from adapters.asb.task_requirements import TaskRequirements
from adapters.asb.task_context import task_checkpoint


REQUEST = 'Summarize the selected report.'


def fixture():
    return {'version': 1, 'issuer': 'independent task owner',
        'reference': 'acceptance criteria ticket', 'tasks': [{
            'request_hash': object_hash(REQUEST), 'requirements': [
                {'id': 'summary', 'description': 'Provide a source-grounded report summary.'},
                {'id': 'gaps', 'description': 'State material missing information honestly.'}]}]}


class TaskRequirementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='tmp')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'requirements.json'

    def load(self, data=None):
        self.path.write_text(json.dumps(data or fixture()), encoding='utf-8')
        return TaskRequirements(self.path)

    def test_exact_binding_and_no_tool_checklist(self):
        requirements = self.load()
        rows = requirements.for_request(REQUEST)
        self.assertEqual([row['id'] for row in rows], ['summary', 'gaps'])
        self.assertNotIn('tool', json.dumps(rows).lower())
        with self.assertRaises(ValueError): requirements.for_request(REQUEST + ' changed')

    def test_rejects_tool_fields_duplicates_and_empty_sets(self):
        for change in ('tool', 'duplicate', 'empty'):
            data = fixture()
            rows = data['tasks'][0]['requirements']
            if change == 'tool': rows[0]['required_tool'] = 'lookup'
            if change == 'duplicate': rows.append(dict(rows[0]))
            if change == 'empty': rows.clear()
            with self.subTest(change=change), self.assertRaises(ValueError): self.load(data)

    def test_progress_separates_receipts_from_requirement_assessment(self):
        requirements = self.load().for_request(REQUEST)
        calls = [{'id': 'call-1', 'tool': 'lookup', 'executed': True,
                  'verdict': 'ALLOW', 'rule': 'review.authorized'},
                 {'id': 'call-2', 'tool': 'write', 'executed': False,
                  'verdict': 'BLOCK', 'rule': 'review.forbidden_effect'}]
        assessment = {'status': 'uncertain', 'requirement_status': [
            {'id': 'summary', 'state': 'evidence_available', 'evidence_ids': ['exec:call-1']},
            {'id': 'gaps', 'state': 'evidence_missing', 'evidence_ids': []}],
            'queries': [], 'missing_information': []}
        progress = task_checkpoint(REQUEST, None, calls, requirements, assessment)
        self.assertEqual(progress['attempted_calls'][0]['state'], 'executed')
        self.assertEqual(progress['attempted_calls'][1]['state'], 'withheld')
        self.assertFalse(progress['executed_calls'][0]['task_completion_verified'])
        self.assertFalse(progress['checkpoint_assessment_is_ground_truth'])
        self.assertEqual(progress['requirements'][0]['checkpoint_assessment']['state'], 'evidence_available')


if __name__ == '__main__': unittest.main()
