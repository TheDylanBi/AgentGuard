"""Strict paired ablations and repeat summaries; no policy or score changes."""
import copy
import statistics


AXES = {'execution': {'execution_recovery'},
        'trust': {'require_tool_contracts', 'require_signed_tool_contracts',
                  'require_complete_tool_contract_coverage'},
        'context': {'action_context'},
        'combined': {'execution_recovery', 'require_tool_contracts'}}


def paired_effect(control, candidate, axis='execution'):
    if axis not in AXES:
        raise ValueError('Unknown ablation axis')
    if (control['mode'] != candidate['mode'] or control['protocol'] != candidate['protocol'] or
            control['policy_code_hash'] != candidate['policy_code_hash']):
        raise ValueError('Ablation requires the same mode, protocol and frozen source')
    first, second = copy.deepcopy(control['comparison']), copy.deepcopy(candidate['comparison'])
    seed = first.get('python_hash_seed', 'random')
    if (not isinstance(seed, str) or not seed.isdecimal() or not 0 <= int(seed) <= 4294967295
            or type(first.get('python_hash_probe')) is not int):
        raise ValueError('Fixed-source ablations require PYTHONHASHSEED at interpreter startup')
    changed = {key for key in set(first) | set(second) if first.get(key) != second.get(key)}
    if changed - AXES[axis] or not changed:
        raise ValueError('Ablation changed an uncontrolled setting, or no experimental setting')
    planned = first['case_ids']
    if len(set(planned)) != len(planned) or not planned:
        raise ValueError('Invalid planned paired selection')
    def indexed(summary):
        rows = summary['cases']
        output = {row['id']: row for row in rows}
        if len(output) != len(rows) or set(output) - set(planned):
            raise ValueError('Duplicate or unplanned outcome')
        return output
    a, b = indexed(control), indexed(candidate)
    scored = [i for i in planned if a.get(i, {}).get('status') == 'complete'
              and b.get(i, {}).get('status') == 'complete']
    unscored = [i for i in planned if i not in scored]
    improved = [i for i in scored if not a[i]['official_original_success'] and b[i]['official_original_success']]
    regressed = [i for i in scored if a[i]['official_original_success'] and not b[i]['official_original_success']]
    scored_a = [i for i in planned if a.get(i, {}).get('status') == 'complete']
    scored_b = [i for i in planned if b.get(i, {}).get('status') == 'complete']
    attacks_a = [i for i in scored_a if a[i].get('official_attack_success') is True]
    attacks_b = [i for i in scored_b if b[i].get('official_attack_success') is True]
    successes_a = sum(bool(a[i]['official_original_success']) for i in scored_a)
    successes_b = sum(bool(b[i]['official_original_success']) for i in scored_b)
    seconds_a = sum(a.get(i, {}).get('elapsed_seconds', 0) for i in planned)
    seconds_b = sum(b.get(i, {}).get('elapsed_seconds', 0) for i in planned)
    return {'axis': axis, 'changed_fields': sorted(changed), 'planned': len(planned),
        'paired_scored': len(scored), 'unscored_ids': unscored,
        'official_complete': not unscored and control['status'] == candidate['status'] == 'complete',
        'control_success': successes_a, 'candidate_success': successes_b,
        'control_score_coverage': len(scored_a) / len(planned),
        'candidate_score_coverage': len(scored_b) / len(planned),
        'control_success_per_planned': successes_a / len(planned),
        'candidate_success_per_planned': successes_b / len(planned),
        'improved_ids': improved, 'regressed_ids': regressed,
        'control_attack_success_ids': attacks_a, 'candidate_attack_success_ids': attacks_b,
        'new_attack_success_ids': sorted(i for i in scored if
            b[i].get('official_attack_success') is True and a[i].get('official_attack_success') is False),
        'unpaired_candidate_attack_success_ids': sorted(set(attacks_b) - set(scored)),
        'elapsed_control_seconds': seconds_a, 'elapsed_candidate_seconds': seconds_b,
        'elapsed_ratio': seconds_b / seconds_a if seconds_a > 0 else None,
        'limits': 'Success counts per planned preserve the denominator; unscored cases are not official failures. '
                  'Paired changes are computed only where both outcomes are scored.'}


def repeated_effect(pairs, gates, *, trust_evidence_available=False):
    if not pairs:
        raise ValueError('No repeated paired outcomes')
    gains = [p['candidate_success'] - p['control_success'] for p in pairs]
    complete = all(p['official_complete'] for p in pairs)
    stable_gain = all(g >= gates['minimum_gain_each_repeat'] for g in gains)
    fewer_attacks = all(len(p['candidate_attack_success_ids']) < len(p['control_attack_success_ids']) for p in pairs)
    new_attacks = sorted({i for p in pairs for i in p['new_attack_success_ids']})
    time_bounded = all(p['elapsed_ratio'] is not None and
                       p['elapsed_ratio'] <= gates['maximum_elapsed_ratio'] for p in pairs)
    checks = {'all_repeats_scored': complete, 'gain_each_repeat': stable_gain,
        'attack_reduction_each_repeat': fewer_attacks, 'no_new_attack_success': not new_attacks,
        'elapsed_growth_bounded': time_bounded,
        'independent_tool_contracts_available': trust_evidence_available}
    ids = sorted({i for p in pairs for i in p['improved_ids'] + p['regressed_ids']})
    return {'repeat_count': len(pairs), 'rounds': pairs, 'net_gain_by_repeat': gains,
        'new_attack_success_ids': new_attacks,
        'direction_unstable_ids': [i for i in ids if any(i in p['improved_ids'] for p in pairs)
                                   and any(i in p['regressed_ids'] for p in pairs)],
        'observed_candidate_success_range': [min(p['candidate_success'] for p in pairs),
                                               max(p['candidate_success'] for p in pairs)],
        'mean_elapsed_ratio': statistics.mean(p['elapsed_ratio'] for p in pairs)
            if all(p['elapsed_ratio'] is not None for p in pairs) else None,
        'gate_checks': checks, 'eligible_for_full_stage': all(checks.values()),
        'default_promotion_authorized': False,
        'limits': 'A failure-enriched pilot and a two-round range are not a population estimate '
                  'or a confidence interval. Repeated tasks are not independent new benchmark samples.'}
