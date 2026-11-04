"""Offline checks that simulation ablations remove exactly their decision gate."""
import unittest
from unittest.mock import Mock

from policy.call_review import CallReviewer
from tests.test_agentdojo_pi import FixtureMixin
from tests.test_call_review import verdict


class AblationTests(FixtureMixin, unittest.TestCase):
    def test_no_review_never_calls_model_but_preserves_hard_gate(self):
        self.manifest['tools']['create_file']['capability']['parameter_constraints'] = {
            'filename': {'enum': ['permitted']}}
        caller = Mock(side_effect=AssertionError('Review must be omitted'))
        host = self.host(reviewer=CallReviewer('Create a file', caller=caller),
                         ablation='no-semantic-review')
        self.assertIsNone(host.call('allowed', 'create_file', {'filename': 'permitted', 'content': 'x'})[1])
        self.assertIsNotNone(host.call('blocked', 'create_file', {'filename': 'outside', 'content': 'x'})[1])
        caller.assert_not_called()
        self.assertEqual(host.counts['executed'], 1)

    def test_no_hard_gate_ignores_parameter_policy_but_keeps_review(self):
        self.manifest['tools']['create_file']['capability']['parameter_constraints'] = {
            'filename': {'enum': ['permitted']}}
        caller = Mock(side_effect=lambda p, **k: verdict(p))
        host = self.host(reviewer=CallReviewer('Create a file', caller=caller), ablation='no-hard-gate')
        self.assertIsNone(host.call('allowed', 'create_file', {'filename': 'outside', 'content': 'x'})[1])
        self.assertEqual(caller.call_count, 1)
        self.assertEqual(host.counts['executed'], 1)

    def test_no_hard_gate_still_honors_semantic_denial(self):
        caller = Mock(side_effect=lambda p, **k: verdict(p, 'deny', 'wrong_target', ['filename']))
        host = self.host(reviewer=CallReviewer('Create a file', caller=caller), ablation='no-hard-gate')
        before = self.env.model_dump()
        self.assertIsNotNone(host.call('denied', 'create_file', {'filename': 'other', 'content': 'x'})[1])
        self.assertEqual(self.env.model_dump(), before)

    def test_baseline_cannot_activate_guard_ablation(self):
        with self.assertRaises(ValueError):
            self.host('baseline', ablation='no-hard-gate')
