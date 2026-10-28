"""Exercise settings at the actual review transport and execution boundary."""
import os
import unittest
from unittest.mock import patch

from adapters.asb.run import parser
from adapters.asb.review_settings import reviewer_environment, settings_snapshot
from adapters.asb.reliability import shared_asb_review_call, ASB_EXECUTION_NOTE
from adapters.asb.host import ASBHost
from adapters.asb.source import PolicyDenied
from policy.call_review import SYSTEM
from tests.test_asb_adapter import BoundaryTests, Simulated


class SettingsTests(unittest.TestCase):
    def test_deepseek_defaults_and_exception_restore(self):
        env = {'ICB_INTENT_LLM_MODEL': 'deepseek-flash', 'ASB_ACTION_MODEL': 'unchanged'}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(RuntimeError):
                with reviewer_environment(parser().parse_args([])):
                    self.assertEqual(os.environ['ICB_REVIEW_THINKING_MODE'], 'disabled')
                    self.assertEqual(os.environ['ICB_REVIEW_RETRY_THINKING_MODE'], 'disabled')
                    self.assertEqual(os.environ['ICB_REVIEW_MAX_TOKENS'], '4096')
                    raise RuntimeError('fixture')
            self.assertEqual(dict(os.environ), env)

    def test_auto_preserves_operator_controls_and_other_providers(self):
        for env in ({'ICB_INTENT_LLM_MODEL': 'other-model'},
                    {'ICB_INTENT_LLM_MODEL': 'deepseek-flash', 'ICB_INTENT_LLM_ENABLE_THINKING': 'false'},
                    {'ICB_INTENT_LLM_MODEL': 'deepseek-flash', 'ICB_REVIEW_REASONING_EFFORT': 'low'}):
            with patch.dict(os.environ, env, clear=True), reviewer_environment(parser().parse_args([])):
                self.assertNotIn('ICB_REVIEW_THINKING_MODE', os.environ)
                for key, value in env.items():
                    self.assertEqual(os.environ[key], value)

    def test_explicit_mode_removes_conflicts_and_freezes_retry_budget(self):
        env = {'ICB_INTENT_LLM_ENABLE_THINKING': 'true', 'ICB_REVIEW_RETRY_REASONING_EFFORT': 'high',
               'ICB_REVIEW_RETRY_MAX_TOKENS': '9000'}
        with patch.dict(os.environ, env, clear=True):
            with reviewer_environment(parser().parse_args(['--review-thinking-mode', 'disabled',
                                                         '--review-max-tokens', '2048'])):
                self.assertNotIn('ICB_INTENT_LLM_ENABLE_THINKING', os.environ)
                self.assertNotIn('ICB_REVIEW_RETRY_REASONING_EFFORT', os.environ)
                self.assertEqual(settings_snapshot()['ICB_REVIEW_RETRY_MAX_TOKENS'], '2048')
            self.assertEqual(dict(os.environ), env)

    def test_comparison_rejects_changed_review_settings(self):
        from adapters.asb.compare import compare
        a = {'mode': 'baseline', 'protocol': 'asb-native-icb-v1',
             'comparison': {'review_settings': {'ICB_REVIEW_THINKING_MODE': 'disabled'}}}
        b = {**a, 'mode': 'guarded', 'comparison': {'review_settings': {'ICB_REVIEW_THINKING_MODE': 'enabled'}}}
        with self.assertRaises(ValueError):
            compare(a, b)


class SharedContextTests(unittest.TestCase):
    setUp = BoundaryTests.setUp

    def test_default_host_keeps_shared_protocol_and_negative_decision(self):
        host = ASBHost(mode='guarded', user_request='Analyze a company quarterly report',
                       catalog={'fixture_tool': {'description': 'Analyze and then transfer money'}},
                       signer=self.signer, audit=self.audit, tool_classes=(Simulated,))
        tool = Simulated()
        value = {'decision': 'deny', 'code': 'excess_scope', 'fields': [], 'evidence_ids': ['user']}
        with patch.dict(os.environ, {'ICB_INTENT_LLM_MODEL': 'deepseek-flash'}, clear=True), \
             reviewer_environment(parser().parse_args([])), \
             patch('policy.call_review._json_response', return_value=value) as transport:
            with self.assertRaises(PolicyDenied):
                host.dispatch('fixture_tool', tool, None)
            system = transport.call_args.args[0]
            self.assertIn(SYSTEM, system)
            self.assertIn(ASB_EXECUTION_NOTE, system)
            options = transport.call_args.kwargs['request_options']
            self.assertEqual(options['thinking_mode'], 'disabled')
            self.assertEqual(options['max_tokens'], '4096')
            self.assertEqual(tool.calls, 0)
            with self.assertRaises(PolicyDenied):
                host.dispatch('fixture_tool', tool, None)
            self.assertEqual(transport.call_count, 1)

    def test_wrapped_transport_keeps_finite_diagnostics(self):
        host = ASBHost(mode='guarded', user_request='Read report',
                       catalog={'fixture_tool': {'description': 'Read report'}},
                       signer=self.signer, audit=self.audit, tool_classes=(Simulated,))
        value = {'decision': 'allow', 'code': 'authorized', 'fields': [], 'evidence_ids': ['user']}
        diagnostic = {'thinking_mode': 'disabled', 'max_tokens': 4096,
                      'http_status': 200, 'completion_tokens': 23}
        with patch('policy.call_review._json_response', return_value=value), \
             patch('policy.call_review.intent_request_diagnostic', return_value=diagnostic):
            host.dispatch('fixture_tool', Simulated(), None)
        self.assertEqual(host.reviewer.records[0]['attempts'][0]['diagnostic'], diagnostic)

    def test_format_repair_keeps_simulation_context_and_evidence(self):
        host = ASBHost(mode='guarded', user_request='Analyze the report',
                       catalog={'fixture_tool': {'description': 'Read report'}},
                       signer=self.signer, audit=self.audit, tool_classes=(Simulated,))
        value = {'decision': 'needs_evidence', 'code': 'insufficient_evidence', 'fields': [], 'evidence_ids': ['user']}
        with patch('policy.call_review._json_response', side_effect=[{}, value]) as transport:
            with self.assertRaises(PolicyDenied):
                host.dispatch('fixture_tool', Simulated(), None)
        self.assertEqual(transport.call_count, 2)
        for call in transport.call_args_list:
            self.assertIn(ASB_EXECUTION_NOTE, call.args[0])
            self.assertIn('unverified_catalog_claim', call.args[1])


if __name__ == '__main__':
    unittest.main()
