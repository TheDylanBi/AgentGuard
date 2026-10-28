"""Run all installed suites' clean user tasks; preserve per-suite official scores."""
import argparse
from collections import Counter
import json
from pathlib import Path
import time

from agentdojo.task_suite import get_suites
from .host import PROJECT
from .run import main as run_suite


def aggregate(plan, root):
    result = {'scope': 'all_suites_clean', 'benchmark_version': plan['benchmark_version'],
              'planned': sum(plan['suites'].values()), 'suites': [], 'successful': 0,
              'scored': 0, 'errors': 0, 'processed': 0, 'attack_success_rate': None}
    complete = True
    categories = Counter()
    for name, count in plan['suites'].items():
        path = root/name/'summary.json'
        row = {'suite': name, 'planned': count, 'summary': str(path), 'status': 'not_started'}
        if path.exists():
            summary = json.loads(path.read_text(encoding='utf-8'))
            entries = (summary.get('official_results') or {}).get('utility_results', [])
            accounting = summary.get('task_accounting', {})
            categories.update(summary.get('task_error_categories') or Counter(
                error.get('error_category','legacy_or_unclassified') for error in summary.get('task_errors',[])))
            row.update(status=summary['status'], successful=sum(x['value'] is True for x in entries),
                       scored=len(entries), errors=len(summary.get('task_errors', [])),
                       processed=accounting.get('processed', len(entries)))
            for key in ('successful', 'scored', 'errors', 'processed'):
                result[key] += row[key]
        if row['status'] not in {'completed', 'completed_with_errors', 'completed_with_stops'}:
            complete = False
        result['suites'].append(row)
    result.update(status='completed' if complete and result['processed'] == result['planned'] else 'incomplete',
                  task_error_categories=dict(categories),
                  scored_unsuccessful=result['scored']-result['successful'],
                  remaining=result['planned']-result['processed'],
                  success_per_planned=result['successful']/result['planned'] if result['planned'] else None,
                  scored_utility=result['successful']/result['scored'] if result['scored'] else None,
                  scoring_coverage=result['scored']/result['planned'] if result['planned'] else None)
    if result['status'] == 'completed' and result['errors']:
        result['status'] = 'completed_with_errors'
    return result


def write_summary(root, value):
    temporary = root/'summary.json.tmp'
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    temporary.replace(root/'summary.json')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--benchmark-version', default='v1.2.2')
    parser.add_argument('--check', action='store_true')
    args, common = parser.parse_known_args(argv)
    forbidden = {'--suite', '--manifest', '--user-task', '--injection-task', '--attack'}
    if any(token.split('=', 1)[0] in forbidden for token in common):
        parser.error('All-suites clean evaluation does not accept suite, manifest, task or attack filters')
    if '--help' in common or '-h' in common:
        print(__doc__+'\nAccepts the same model/security options as adapters.agentdojo_pi.run. '
              'No task/attack filters. --check validates every suite without model calls.')
        return 0
    suites = get_suites(args.benchmark_version)
    plan = {'benchmark_version': args.benchmark_version,
            'suites': {name: len(suite.user_tasks) for name, suite in suites.items()}}
    # Validate EVERY manifest and local dependency before spending model tokens.
    for name in suites:
        run_suite([*common, '--suite', name, '--benchmark-version', args.benchmark_version, '--check'])
    if args.check:
        print(json.dumps({**plan, 'user_tasks_total': sum(plan['suites'].values()),
                          'status': 'configuration_valid', 'model_calls': 0}, indent=2))
        return 0
    root = (args.output or PROJECT/'results'/f'agentdojo_pi_all_clean_{time.time_ns()}').resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root/'plan.json').write_text(json.dumps(plan, indent=2)+'\n', encoding='utf-8')
    write_summary(root, aggregate(plan, root))
    print('All-suite results: '+str(root/'summary.json'), flush=True)
    failures = []
    try:
        for index, (name, count) in enumerate(plan['suites'].items(), 1):
            print(f'Suite {index}/{len(suites)}: {name}, {count} clean user tasks', flush=True)
            try:
                code = run_suite([*common, '--suite', name, '--benchmark-version', args.benchmark_version,
                                  '--output', str(root/name)])
                if code:
                    failures.append({'suite': name, 'exit_code': code})
            except Exception as error:
                # Keep the original per-suite summary/diagnostics; do not turn
                # a missing result into a scored failure or a defense success.
                failures.append({'suite': name, 'error_type': type(error).__name__})
            write_summary(root, {**aggregate(plan, root), 'suite_errors': failures})
    finally:
        write_summary(root, {**aggregate(plan, root), 'suite_errors': failures})
        print('All-suite results: '+str(root/'summary.json'), flush=True)
    return 1 if failures or aggregate(plan, root)['status'] == 'incomplete' else 0


if __name__ == '__main__':
    raise SystemExit(main())
