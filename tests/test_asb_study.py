import copy
import unittest
from adapters.asb.study import paired_effect, repeated_effect


def summary(recovery='native', outcomes=(True, False), attacks=(True, False)):
    return {'mode': 'guarded', 'protocol': 'native', 'policy_code_hash': 'fixed', 'status': 'complete',
        'comparison': {'case_ids': ['a', 'b'], 'model': 'same-model',
                       'python_hash_seed': '0', 'python_hash_probe': 123,
                       'execution_recovery': recovery, 'require_tool_contracts': False},
        'cases': [{'id': i, 'status': 'complete', 'official_original_success': success,
                   'official_attack_success': attack, 'elapsed_seconds': 10}
                  for i, success, attack in zip(('a', 'b'), outcomes, attacks)]}


class PairedStudyTests(unittest.TestCase):
    def test_context_ablation_changes_no_other_execution_or_trust_settings(self):
        a, b = summary(), summary()
        a['comparison']['action_context'] = 'native'
        b['comparison']['action_context'] = 'structured'
        self.assertEqual(paired_effect(a, b, axis='context')['changed_fields'], ['action_context'])
        b['comparison']['require_tool_contracts'] = True
        with self.assertRaises(ValueError): paired_effect(a, b, axis='context')

    def test_separate_gains_losses_and_new_attacks(self):
        value = paired_effect(summary(), summary('checkpoint', (False, True), (False, True)))
        self.assertEqual(value['improved_ids'], ['b'])
        self.assertEqual(value['regressed_ids'], ['a'])
        self.assertEqual(value['new_attack_success_ids'], ['b'])

    def test_drift_in_model_context_source_or_selection_is_rejected(self):
        for field in ('model', 'case_ids', 'policy_code_hash', 'protocol'):
            a, b = summary(), summary('checkpoint')
            if field in b['comparison']:
                b['comparison'][field] = ['b', 'a'] if field == 'case_ids' else 'changed'
            else:
                b[field] = 'changed'
            with self.subTest(field=field), self.assertRaises(ValueError): paired_effect(a, b)

    def test_hash_randomization_or_late_environment_change_is_detected(self):
        a, b = summary(), summary('checkpoint')
        a['comparison']['python_hash_seed'] = 'random'
        with self.assertRaises(ValueError): paired_effect(a, b)
        a = summary()
        b['comparison']['python_hash_probe'] = 999
        with self.assertRaises(ValueError): paired_effect(a, b)

    def test_trust_factor_does_not_change_task_or_supply_a_different_manifest(self):
        a, b = summary(), summary()
        a['comparison']['tool_contracts_hash'] = b['comparison']['tool_contracts_hash'] = 'operator-manifest'
        b['comparison']['require_tool_contracts'] = True
        self.assertEqual(paired_effect(a, b, axis='trust')['changed_fields'], ['require_tool_contracts'])
        b['comparison']['tool_contracts_hash'] = 'another-manifest'
        with self.assertRaises(ValueError): paired_effect(a, b, axis='trust')

    def test_unscored_error_is_preserved_and_never_becomes_a_paired_failure(self):
        a, b = summary(), summary('checkpoint', (True, True), (False, False))
        b['status'] = 'incomplete'
        b['cases'][1] = {'id': 'b', 'status': 'incomplete'}
        value = paired_effect(a, b)
        self.assertEqual(value['unscored_ids'], ['b'])
        self.assertEqual(value['improved_ids'], [])
        self.assertEqual(value['planned'], 2)
        self.assertFalse(value['official_complete'])
        self.assertEqual(value['control_score_coverage'], 1)
        self.assertEqual(value['candidate_score_coverage'], 0.5)
        self.assertEqual(value['control_success'], 1)

    def test_missing_contracts_blocks_full_stage_even_with_apparent_gains(self):
        pair = paired_effect(summary(outcomes=(False, False)),
                             summary('checkpoint', (True, True), (False, False)))
        gates = {'minimum_gain_each_repeat': 2, 'maximum_elapsed_ratio': 1.5}
        result = repeated_effect([pair, copy.deepcopy(pair)], gates)
        self.assertFalse(result['eligible_for_full_stage'])
        self.assertFalse(result['gate_checks']['independent_tool_contracts_available'])

    def test_repeat_regression_or_new_attack_cannot_be_hidden_by_a_mean(self):
        good = paired_effect(summary(outcomes=(False, False)),
            summary('checkpoint', (True, True), (False, False)))
        bad = paired_effect(summary(), summary('checkpoint', (False, True), (False, True)))
        result = repeated_effect([good, bad], {'minimum_gain_each_repeat': 1,
            'maximum_elapsed_ratio': 1.5}, trust_evidence_available=True)
        self.assertFalse(result['eligible_for_full_stage'])
        self.assertFalse(result['gate_checks']['no_new_attack_success'])


if __name__ == '__main__': unittest.main()
