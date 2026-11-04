"""Evaluate clean model capability through AgentDojo's benchmark CLI.

Example (PowerShell, activated agentdojo environment):
  $env:OPENAI_COMPATIBLE_API_KEY = <your provider key>
  python -X utf8 -B tools/eval_agentdojo_models.py --base-url <API URL> --models <model ID>
  python -X utf8 -B tools/eval_agentdojo_models.py --models model-a model-b --check

Models in one invocation share an OpenAI-compatible endpoint. Run separately for
different endpoints. No keys are accepted as command-line arguments or saved in
the wrapper summary. Native AgentDojo logs are retained under each model folder.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
import uuid


def write_json(path, value):
    temporary = path.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def configure_system_role(role):
    """Keep native content and tool serialization; select the provider's role."""
    from agentdojo.agent_pipeline.llms import openai_llm
    original = openai_llm._message_to_openai

    def serialize(message, model_name):
        result = original(message, model_name)
        if message['role'] == 'system':
            result = {**result, 'role': role}
        return result

    openai_llm._message_to_openai = serialize


def summarize(logdir, expected):
    records = {}
    for path in logdir.rglob('*.json'):
        value = json.loads(path.read_text(encoding='utf-8'))
        key = (value.get('suite_name'), value.get('user_task_id'))
        if key not in expected or value.get('attack_type') not in (None, 'none'):
            continue
        if key in records:
            raise ValueError('Duplicate official task logs')
        records[key] = value
    rows = []
    for suite, task in expected:
        value = records.get((suite, task))
        rows.append({'suite': suite, 'user_task': task,
                     'status': 'missing' if value is None else 'error' if value.get('error')
                     else 'scored' if type(value.get('utility')) is bool else 'unscored',
                     'official_utility': value.get('utility') if value else None,
                     'elapsed_seconds': value.get('duration') if value else None})
    scored = [row for row in rows if row['status'] == 'scored']
    durations = [row['elapsed_seconds'] for row in scored
                 if isinstance(row['elapsed_seconds'], (int, float))]
    successful = sum(row['official_utility'] is True for row in scored)
    return {'planned': len(rows), 'scored': len(scored), 'successful': successful,
            'errors': sum(row['status'] == 'error' for row in rows),
            'missing_or_unscored': sum(row['status'] in ('missing', 'unscored') for row in rows),
            'scoring_coverage': len(scored) / len(rows),
            'utility_on_scored': successful / len(scored) if scored else None,
            'confirmed_success_per_planned': successful / len(rows),
            'mean_task_seconds_on_scored': statistics.mean(durations) if durations else None,
            'median_task_seconds_on_scored': statistics.median(durations) if durations else None,
            'task_outcomes': rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--models', nargs='+', required=True, help='Exact model IDs served by one endpoint')
    parser.add_argument('--base-url', default=os.getenv('OPENAI_COMPATIBLE_BASE_URL'))
    parser.add_argument('--api-key-env', default='OPENAI_COMPATIBLE_API_KEY')
    parser.add_argument('--suite', action='append', choices=('workspace', 'travel', 'banking', 'slack'))
    parser.add_argument('--user-task', action='append', help='Optional smoke selection; requires exactly one suite')
    parser.add_argument('--benchmark-version', default='v1.2.2')
    parser.add_argument('--system-role', choices=('system', 'developer'), default='system',
                        help='API role for native system instructions; default system for compatible providers')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', action='store_true', help='Validate local entry point and task plan, no model requests')
    args = parser.parse_args(argv)
    if len(args.models) != len(set(args.models)):
        parser.error('Duplicate model IDs')
    if any(model.startswith('sk-') for model in args.models):
        parser.error('A model ID looks like an API key; supply the model name')
    suites = args.suite or ['workspace', 'travel', 'banking', 'slack']
    if len(suites) != len(set(suites)) or (args.user_task and len(suites) != 1):
        parser.error('Select unique suites; user-task requires one suite')
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.models import ModelsEnum
    import agentdojo.scripts.benchmark as benchmark_module
    if 'openai-compatible' not in [item.value for item in ModelsEnum]:
        parser.error('Installed AgentDojo lacks openai-compatible support; use the local F:/Datasets/agentdojo checkout')
    # Click versions differ in whether enum choices accept names or values.
    # Validate against the installed CLI's actual parameter before starting jobs.
    import click
    model_option = next(param for param in benchmark_module.main.params if param.name == 'model')
    model_token = None
    for candidate in (ModelsEnum.OPENAI_COMPATIBLE.name, ModelsEnum.OPENAI_COMPATIBLE.value):
        try:
            model_option.type.convert(candidate, model_option, None)
        except click.BadParameter:
            continue
        model_token = candidate
        break
    if model_token is None:
        parser.error('Installed benchmark CLI does not accept the compatible model provider')
    expected = []
    for name in suites:
        suite = get_suite(args.benchmark_version, name)
        tasks = args.user_task or list(suite.user_tasks)
        if len(tasks) != len(set(tasks)) or any(task not in suite.user_tasks for task in tasks):
            parser.error('Unknown or duplicate user task')
        expected.extend((name, task) for task in tasks)
    print(f'Native AgentDojo capability evaluation: {len(expected)} clean tasks per model', flush=True)
    if args.check:
        subprocess.run([sys.executable, '-X', 'utf8', '-B', '-m', 'agentdojo.scripts.benchmark', '--help'],
                       check=True, stdout=subprocess.DEVNULL)
        print(json.dumps({'status': 'configuration_valid', 'models': args.models,
                          'planned_per_model': len(expected), 'model_calls': 0,
                          'cli_model_token': model_token,
                          'system_role': args.system_role,
                          'benchmark_entry': str(Path(benchmark_module.__file__).resolve())}, indent=2))
        return 0
    if not args.base_url or not os.getenv(args.api_key_env):
        parser.error('Supply --base-url and set the environment variable named by --api-key-env')
    env = {**os.environ, 'OPENAI_COMPATIBLE_BASE_URL': args.base_url,
           'OPENAI_COMPATIBLE_API_KEY': os.environ[args.api_key_env], 'PYTHONUTF8': '1'}
    root = (args.output or Path('results') / ('agentdojo_native_clean_' + uuid.uuid4().hex)).resolve()
    root.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'pipeline': 'native_agentdojo_cli', 'attack': None, 'defense': None,
              'system_role': args.system_role,
              'benchmark_version': args.benchmark_version, 'planned_per_model': len(expected),
              'started_utc': datetime.now(timezone.utc).isoformat(),
              'benchmark_entry': str(Path(benchmark_module.__file__).resolve()),
              'benchmark_entry_sha256': hashlib.sha256(Path(benchmark_module.__file__).read_bytes()).hexdigest(),
              'wrapper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'endpoint_sha256': hashlib.sha256(args.base_url.encode()).hexdigest(), 'models': []}
    write_json(root / 'summary.json', report)
    try:
        for index, model in enumerate(args.models, 1):
            modeldir = root / f'model_{index:02d}'
            logdir = modeldir / 'official'
            logdir.mkdir(parents=True)
            row = {'model': model, 'directory': str(modeldir), 'status': 'running', 'suite_exit_codes': {}}
            report['models'].append(row)
            write_json(root / 'summary.json', report)
            start = time.monotonic()
            for suite in suites:
                command = [sys.executable, '-X', 'utf8', '-B', str(Path(__file__).resolve()),
                           '--native-worker', args.system_role,
                           '--model', model_token, '--model-id', model, '--suite', suite,
                           '--benchmark-version', args.benchmark_version, '--logdir', str(logdir)]
                for task in args.user_task or []:
                    command.extend(['--user-task', task])
                print(f'[{index}/{len(args.models)}] {model} / {suite}', flush=True)
                row['suite_exit_codes'][suite] = subprocess.run(command, env=env).returncode
                row.update(summarize(logdir, expected))
                write_json(modeldir / 'summary.json', row)
                write_json(root / 'summary.json', report)
            row['wall_seconds'] = round(time.monotonic() - start, 3)
            row['status'] = 'completed' if row['scored'] == len(expected) and not any(row['suite_exit_codes'].values()) else 'incomplete'
            write_json(modeldir / 'summary.json', row)
        report['status'] = 'completed' if all(row['status'] == 'completed' for row in report['models']) else 'incomplete'
    finally:
        if report['status'] == 'running':
            report['status'] = 'interrupted_or_failed'
        write_json(root / 'summary.json', report)
        print('Results: ' + str(root / 'summary.json'), flush=True)
    return 0 if report['status'] == 'completed' else 1


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--native-worker':
        role = sys.argv[2]
        if role not in ('system', 'developer'):
            raise SystemExit('Invalid worker system role')
        configure_system_role(role)
        from agentdojo.scripts.benchmark import main as official_main
        official_main.main(args=sys.argv[3:])
    else:
        raise SystemExit(main())
