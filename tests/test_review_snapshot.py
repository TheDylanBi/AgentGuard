"""Replay invariants; semantic correctness is checked separately with real models."""
import copy
import json
import os
import unittest
from unittest.mock import Mock, patch

from policy.call_review import ReviewStageError, review_call
from policy.review_snapshot import (capture_review_inputs, replay_review_input,
    validate_snapshot, ReviewSnapshotError, effective_options)
from adapters.asb.review_cases import review_cases, case_snapshot
from adapters.asb.review_replay import repeat_snapshot


ALLOW = {'decision': 'allow', 'code': 'authorized', 'fields': [], 'evidence_ids': ['user']}
DENY = {'decision': 'deny', 'code': 'outside_task', 'fields': [], 'evidence_ids': ['user']}


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        context = patch.dict(os.environ, {'ICB_INTENT_LLM_MODEL': 'fixture-model',
            'ICB_INTENT_LLM_BASE_URL': 'https://fixture.invalid/v1',
            'ICB_INTENT_LLM_API_KEY': 'TOP_SECRET_ENV_KEY'})
        context.start()
        self.addCleanup(context.stop)
        self.cases = review_cases()
        self.snapshot = case_snapshot(self.cases[0])

    def test_preparation_has_no_model_request_and_hides_oracles_and_credentials(self):
        with patch('requests.post', side_effect=AssertionError('No transport during capture')) as post:
            snapshots = [case_snapshot(c) for c in self.cases]
        post.assert_not_called()
        for value in snapshots:
            validate_snapshot(value)
            user = json.loads(value['request']['user'])
            self.assertNotIn('expected', user)
            self.assertNotIn('oracle', user)
            self.assertNotIn('TOP_SECRET_ENV_KEY', json.dumps(value))

    def test_replay_sends_exact_saved_request_and_frozen_options(self):
        transport = Mock(return_value=ALLOW)
        with patch.dict(os.environ, {'ICB_INTENT_LLM_MAX_TOKENS': '17', 'ICB_REVIEW_THINKING_MODE': 'enabled'}):
            result = replay_review_input(self.snapshot, transport=transport)
        request = self.snapshot['request']
        transport.assert_called_once_with(request['system'], request['user'], request['schema'],
            timeout_seconds=self.snapshot['client_budget']['timeout_seconds'], request_options=request['options'])
        self.assertEqual(result['decision'], 'allow')

    def test_altered_snapshot_fails_before_transport(self):
        value = copy.deepcopy(self.snapshot)
        value['request']['user'] += 'changed'
        transport = Mock()
        with self.assertRaisesRegex(ReviewSnapshotError, 'hash_mismatch'):
            replay_review_input(value, transport=transport)
        transport.assert_not_called()

    def test_changed_endpoint_or_model_is_not_silently_compared(self):
        for setting in ({'ICB_INTENT_LLM_MODEL': 'another-model'},
                        {'ICB_INTENT_LLM_BASE_URL': 'https://another.invalid/v1'}):
            with patch.dict(os.environ, setting), self.assertRaisesRegex(ReviewSnapshotError, 'model_or_endpoint'):
                replay_review_input(self.snapshot, transport=Mock())

    def test_changed_runtime_is_not_silently_compared(self):
        with patch('policy.review_snapshot.runtime_identity', return_value={}), \
                self.assertRaisesRegex(ReviewSnapshotError, 'runtime_changed'):
            replay_review_input(self.snapshot, transport=Mock())

    def test_changed_transport_budget_is_explicit(self):
        original = os.environ.get('ICB_INTENT_LLM_TIMEOUT_SECONDS', '30')
        with patch.dict(os.environ, {'ICB_INTENT_LLM_TIMEOUT_SECONDS': '29' if original != '29' else '28'}), \
                self.assertRaisesRegex(ReviewSnapshotError, 'timeout_changed'):
            replay_review_input(self.snapshot, transport=Mock())

    def test_wire_citations_map_only_to_host_issued_handles(self):
        snapshot = case_snapshot(self.cases[7])
        reply = {**DENY, 'evidence_ids': ['user', 'e1']}
        result = replay_review_input(snapshot, transport=Mock(return_value=reply))
        self.assertIn('obs:prior', result['evidence_ids'])
        with self.assertRaises(ReviewStageError):
            replay_review_input(snapshot, transport=Mock(return_value={**DENY, 'evidence_ids': ['obs:prior']}))

    def test_invalid_response_is_not_repaired_or_turned_into_allow(self):
        transport = Mock(return_value={'decision': 'allow'})
        with self.assertRaises(ReviewStageError):replay_review_input(self.snapshot, transport=transport)
        transport.assert_called_once()

    def test_offline_repetitions_measure_denials_without_live_recovery(self):
        runner = Mock(return_value=DENY)
        result = repeat_snapshot(self.snapshot, repeats=3, runner=runner)
        self.assertEqual(runner.call_count, 3)
        self.assertEqual(result['decisions'], {'allow': 0, 'deny': 3, 'needs_evidence': 0})
        self.assertFalse(result['decision_disagreement'])

    def test_protocol_errors_remain_in_denominator(self):
        runner = Mock(side_effect=[ALLOW, ReviewStageError({'status': 'invalid_review'}), DENY])
        result = repeat_snapshot(self.snapshot, 3, runner=runner)
        self.assertEqual((result['planned'], result['valid'], result['errors']), (3, 2, 1))
        self.assertTrue(result['decision_disagreement'])

    def test_provider_credit_error_stops_and_preserves_unattempted_samples(self):
        runner = Mock(side_effect=ReviewStageError({'http_status': 402}))
        result = repeat_snapshot(self.snapshot, 5, runner=runner)
        self.assertEqual(result['status'], 'incomplete')
        self.assertEqual((result['valid'], result['errors'], result['unattempted']), (0, 1, 4))

    def test_interrupt_persists_partial_results(self):
        saved = []
        runner = Mock(side_effect=[DENY, KeyboardInterrupt()])
        with self.assertRaises(KeyboardInterrupt):
            repeat_snapshot(self.snapshot, 3, runner=runner, on_update=lambda r: saved.append(copy.deepcopy(r)))
        self.assertEqual(saved[-1]['status'], 'incomplete')
        self.assertEqual(saved[-1]['unattempted'], 2)

    def test_capture_context_is_reset_after_failure(self):
        first, second = [], []
        with capture_review_inputs(first.append):
            nested = case_snapshot(self.cases[0])
        self.assertEqual(first, [])  # Nested fixture sink must not escape.
        with capture_review_inputs(second.append), patch('policy.call_review._json_response', return_value=ALLOW):
            review_call(nested['packet'])
        self.assertEqual(len(second), 1)

    def test_scope_profile_is_opt_in_and_frozen_in_the_prompt(self):
        with patch.dict(os.environ, {'ICB_REVIEW_AUTHORIZATION_PROFILE': 'standard'}):
            standard = case_snapshot(self.cases[0])
        with patch.dict(os.environ, {'ICB_REVIEW_AUTHORIZATION_PROFILE': 'scope'}):
            scope = case_snapshot(self.cases[0])
        self.assertNotEqual(standard['request']['system'], scope['request']['system'])
        self.assertEqual(standard['request']['user'], scope['request']['user'])
        self.assertEqual(standard['request']['schema'], scope['request']['schema'])


if __name__ == '__main__':
    unittest.main()
