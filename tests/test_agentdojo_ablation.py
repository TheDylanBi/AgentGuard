"""Offline checks that simulation ablations remove exactly their decision gate."""
import unittest
from unittest.mock import Mock, patch

from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from adapters.agentdojo_pi.host import PROJECT, load_manifest
from policy.call_review import CallReviewer, ReviewStageError
from policy.resource_handles import REF, ResourceReferenceError
from tests.test_agentdojo_pi import FixtureMixin
from tests.test_call_review import verdict
from tests.test_role_data_flow import citing


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

    def test_no_review_checks_the_state_binding(self):
        caller = Mock(side_effect=AssertionError('Review must be omitted'))
        host = self.host(reviewer=CallReviewer('Create a file', caller=caller),
                         ablation='no-semantic-review')
        with patch.object(host, '_execution_boundary_hash', side_effect=['before', 'changed']), \
                patch.object(host.runtime, 'run_function') as dispatch:
            with self.assertRaises(ReviewStageError) as error:
                host.call('changed', 'create_file', {'filename': 'fixture', 'content': 'x'})
        self.assertEqual(error.exception.diagnostic['status'], 'review_state_changed')
        caller.assert_not_called()
        dispatch.assert_not_called()

    def test_no_hard_gate_checks_the_state_binding(self):
        def review(packet, **kwargs):
            host.spent_typed_sources.add('fixture')
            return verdict(packet)

        host = self.host(reviewer=CallReviewer('Create a file', caller=review), ablation='no-hard-gate')
        with patch.object(host.runtime, 'run_function') as dispatch:
            with self.assertRaises(ReviewStageError) as error:
                host.call('changed', 'create_file', {'filename': 'fixture', 'content': 'x'})
        self.assertEqual(error.exception.diagnostic['status'], 'review_state_changed')
        dispatch.assert_not_called()

    def test_no_execution_recheck_keeps_hard_gate_and_semantic_denial(self):
        self.manifest['tools']['create_file']['capability']['parameter_constraints'] = {
            'filename': {'enum': ['permitted']}}
        caller = Mock(side_effect=lambda p, **k: verdict(p, 'deny', 'wrong_target', ['filename']))
        hard_gate = self.host(reviewer=CallReviewer('Create a file', caller=caller),
                              ablation='no-execution-recheck')
        semantic_gate = self.host(reviewer=CallReviewer('Create a file', caller=caller),
                                  ablation='no-execution-recheck')
        with patch.object(self.runtime, 'run_function') as dispatch:
            self.assertIsNotNone(hard_gate.call('hard-denial', 'create_file',
                                                {'filename': 'outside', 'content': 'x'})[1])
            caller.assert_not_called()
            self.assertIsNotNone(semantic_gate.call('semantic-denial', 'create_file',
                                                    {'filename': 'permitted', 'content': 'x'})[1])
        caller.assert_called_once()
        dispatch.assert_not_called()

    def test_no_execution_recheck_keeps_initial_resolution_and_skips_revalidation(self):
        suite = get_suite('v1.2.2', 'slack')
        self.runtime = FunctionsRuntime(suite.tools)
        self.env = suite.load_and_inject_default_environment({})
        self.manifest = load_manifest(PROJECT / 'adapters/agentdojo_pi/slack_manifest.json', self.runtime)
        host = self.host(reviewer=CallReviewer('Read every channel.', caller=citing),
                         ablation='no-execution-recheck')
        self.assertIsNone(host.call('list', 'get_channels', {})[1])
        ref = next(ref for ref, row in host.resource_handles.records.items()
                   if row['selector'][1] == 'channel_name' and row['key'] == 'general')
        resolve = host.resource_handles.materialize
        with patch.object(host.resource_handles, 'materialize', side_effect=resolve) as materialize, \
                patch.object(host, '_execution_boundary_hash') as boundary_hash, \
                patch.object(host.runtime, 'run_function', return_value=([], None)) as dispatch:
            self.assertIsNone(host.call('read', 'read_channel_messages', {'channel': {REF: ref}})[1])
        materialize.assert_called_once()
        boundary_hash.assert_not_called()
        dispatch.assert_called_once_with(self.env, 'read_channel_messages', {'channel': 'general'})
        self.assertEqual(host.audit.get('read:start')['binding_revalidation'],
                         {'state': False, 'resource_reference': False})

        with patch.object(host.resource_handles, 'materialize',
                          side_effect=ResourceReferenceError('stale', 'channel')), \
                patch.object(host.runtime, 'run_function') as dispatch:
            self.assertIsNotNone(host.call('stale', 'read_channel_messages', {'channel': {REF: ref}})[1])
        dispatch.assert_not_called()
