"""Compare matching ASB baseline/guarded summaries without silently dropping errors."""
import argparse
import json
from pathlib import Path


def compare(baseline, guarded):
    if baseline['mode'] != 'baseline' or guarded['mode'] != 'guarded':
        raise ValueError('Expected baseline followed by guarded')
    for key in ('python_hash_seed', 'python_hash_probe'):
        if baseline['comparison'].get(key) != guarded['comparison'].get(key):
            raise ValueError('Python tool ordering differs; set PYTHONHASHSEED before starting both interpreters')
    if baseline['protocol'] != guarded['protocol'] or baseline['comparison'] != guarded['comparison']:
        raise ValueError('ASB model, source, selection or execution settings differ')
    if baseline['policy_code_hash'] != guarded['policy_code_hash']:
        raise ValueError('Policy/adapter source changed between runs; rerun baseline')
    if baseline['status'] != 'complete' or guarded['status'] != 'complete':
        raise ValueError('Incomplete ASB runs cannot produce a defense effectiveness score')
    first, second = baseline['metrics'], guarded['metrics']
    output = {'protocol': baseline['protocol'], 'attack': baseline['comparison']['attack'],
        'selected': first['selected'], 'baseline': first, 'guarded': second}
    for metric in ('official_attack_success_rate', 'official_original_task_success_rate', 'executed_attacker_tool_rate'):
        a, b = first[metric], second[metric]
        output[metric + '_change_pp'] = None if a is None or b is None else round(100 * (b-a), 4)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--guarded', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    result = compare(json.loads(args.baseline.read_text(encoding='utf-8')),
                     json.loads(args.guarded.read_text(encoding='utf-8')))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
