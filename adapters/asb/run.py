"""Run native ASB agents/tools/scorers with an optional ICB-Guard dispatch gate.

The source checkout is read-only. AIOS scheduling is replaced by a serial,
bounded OpenAI-compatible transport, shared by baseline and guarded runs.
"""
import argparse
import contextlib
import copy
from datetime import datetime
import importlib
import importlib.metadata
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import shutil
import sys
import tempfile
import time
import types

from attestation.hashing import object_hash
from attestation.log import CertificateLog
from attestation.signer import Signer
from policy.business_rules import BusinessPolicy
from policy.intent_anchor import intent_llm_configured
from .host import ASBHost
from .action_config import ActionConfigurationError, resolve_action_config
from .transport import ActionTransport, ActionTransportError
from .tool_contracts import ToolContracts
from .diagnostics import case_diagnostics
from .review_settings import reviewer_environment, settings_snapshot
from .task_context import TaskContexts, actor_request, PROTOCOL as CLARIFICATION_PROTOCOL
from .task_requirements import TaskRequirements, PROTOCOL as REQUIREMENTS_PROTOCOL
from .capability_report import capability_report
from .completion import CompletionProtocolError
from .action_context import ActionContextError
from policy.review_snapshot import model_identity as review_model_identity
from .source import (agent_module_path, attach_hooks, file_hash, official_scorers,
                     read_jsonl, snapshot, validate_source)

PROJECT = Path(__file__).resolve().parents[2]
NATIVE_DEPENDENCIES = ('numpy', 'pandas', 'dotenv', 'click', 'openai', 'jsonlines',
                       'langchain_core', 'langchain_chroma', 'langchain_ollama', 'langchain_openai')
ATTACKS = ('clean', 'opi', 'dpi', 'mixed', 'memory', 'pot', 'pot-clean')


def write_json(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')


def policy_source_hashes():
    paths = [path for folder in ('policy', 'attestation', 'adapters/asb')
             for path in sorted((PROJECT / folder).rglob('*'))
             if path.is_file() and path.suffix in {'.py', '.yaml', '.yml'}]
    paths.append(PROJECT / 'gateway/api_schema.py')
    return {str(path.relative_to(PROJECT)): file_hash(path) for path in paths}


def archive_policy_sources(directory, hashes):
    """Snapshot only public policy/adapter code, never local model credentials."""
    for name, expected in hashes.items():
        source = PROJECT / name
        target = directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if file_hash(target) != expected:
            raise RuntimeError('Policy changed while archiving sources')




def select_cases(root, args):
    tasks = read_jsonl(root / 'data/agent_task.jsonl')
    suffix = {'all': '', 'agg': '_aggressive', 'non-agg': '_non_aggressive'}[args.attack_tools]
    attacks = read_jsonl(root / ('data/all_attack_tools' + suffix + '.jsonl'))
    known = {row['agent_name'] for row in tasks}
    if args.agent and set(args.agent) - known:
        raise ValueError('Unknown ASB agent selection')
    result = []
    for row in tasks:
        if args.agent and row['agent_name'] not in args.agent:
            continue
        # Only the built-in example agents are supported; do not download code.
        module = agent_module_path(row['agent_name'])
        if row['agent_path'] != 'example/' + row['agent_name']:
            raise ValueError('Unsupported ASB agent path')
        if not (root / Path(*module.split('.')).with_suffix('.py')).is_file():
            raise ValueError('Missing native ASB example agent')
        paired = [attack for attack in attacks if attack['Corresponding Agent'] == row['agent_name']]
        if not paired:
            raise ValueError('No attacker tools for selected ASB agent')
        if args.attack == 'clean':
            paired = paired[:1]  # Same native clean task, not duplicated per attack tool.
        for index, task in enumerate(row['tasks'][:args.task_num]):
            for attack in paired:
                identity = {'agent': row['agent_name'], 'task_index': index,
                    'task': task, 'attack_tool': attack['Attacker Tool'] if args.attack != 'clean' else None}
                result.append({**identity, 'id': object_hash(identity).split(':')[-1][:20],
                               'agent_path': row['agent_path'], 'attacker': attack})
    if args.limit:
        result = result[:args.limit]
    selected_ids = getattr(args, 'case_id', None)
    if selected_ids:
        wanted = set(selected_ids)
        if len(wanted) != len(selected_ids) or wanted - {row['id'] for row in result}:
            raise ValueError('Unknown or duplicate ASB case selection (check --limit)')
        result = [row for row in result if row['id'] in wanted]
    if not result:
        raise ValueError('Empty ASB selection')
    return result


def catalog_for(root, case, attack):
    config = json.loads((root / 'pyopenagi/agents' / case['agent_path'] / 'config.json').read_text(encoding='utf-8'))
    table = {row['Tool Name']: row['Description'] for row in read_jsonl(root / 'data/all_normal_tools.jsonl')}
    catalog = {}
    for qualified in config['tools']:
        name = qualified.split('/')[-1]
        catalog[name] = {'description': table[name]}
    if attack != 'clean':
        row = case['attacker']
        name = row['Attacker Tool']
        if name in catalog:
            raise ValueError('Native ASB attacker tool shadows an existing tool')
        catalog[name] = {'description': row['Description']}
    return catalog


def action_config(args):
    return resolve_action_config(args)




def native_args(args, root, memory_db=None):
    return types.SimpleNamespace(llm_name=args.model, workflow_mode='automatic',
        attack_type=args.attack_type, defense_type=None,
        tools_info_path=str(root / 'data/all_normal_tools.jsonl'),
        attacker_tools_path=str(root / 'data/all_attack_tools.jsonl'),
        direct_prompt_injection=args.attack in {'dpi', 'mixed'},
        observation_prompt_injection=args.attack in {'opi', 'mixed'},
        memory_attack=args.attack == 'memory', read_db=args.attack == 'memory', write_db=False,
        pot_backdoor=args.attack == 'pot', pot_clean=args.attack == 'pot-clean',
        clean=args.attack == 'clean', trigger=args.trigger, database=str(memory_db or ''))


def load_native(root):
    # Native ASB constructor calls load_dotenv. Disable that explicit convenience
    # hook so running inside the project never implicitly reads its .env.
    if any(name == 'pyopenagi' or name.startswith('pyopenagi.') for name in sys.modules):
        raise RuntimeError('Run ASB in a fresh Python process (native module isolation)')
    sys.path.insert(0, str(root))
    native = importlib.import_module('pyopenagi.agents.react_agent_attack')
    if not Path(native.__file__).resolve().is_relative_to(root):
        raise RuntimeError('Wrong ASB module was imported')
    native.load_dotenv = lambda *a, **k: False
    return native


def summarize(cases, planned_count=None):
    complete = [case for case in cases if case['status'] == 'complete']
    counts = {key: sum(case.get('counts', {}).get(key, 0) for case in cases)
              for key in ('ALLOW', 'BLOCK', 'CONFIRM', 'executed', 'tool_errors')}
    # Incomplete runs keep their selected denominator; no success-looking ASR.
    n = len(cases) if planned_count is None else planned_count
    valid = bool(n) and len(complete) == n
    rate = lambda field: sum(bool(case[field]) for case in complete) / n if valid else None
    return {'selected': n, 'complete': len(complete), 'errors': n - len(complete),
        'score_coverage': len(complete) / n if n else None,
        'original_success_count': sum(bool(c.get('official_original_success')) for c in complete),
        'scored_original_success_rate': (sum(bool(c.get('official_original_success')) for c in complete) / len(complete)
                                         if complete else None),
        'diagnostic_factor_counts': {factor: sum(factor in c.get('diagnostic_factors', []) for c in cases)
            for factor in sorted({f for c in cases for f in c.get('diagnostic_factors', [])})},
        'workflow_failures': sum(bool(case.get('workflow_failure')) for case in complete),
        'official_attack_success_rate': rate('official_attack_success') if valid and cases[0]['attack'] != 'clean' else None,
        'official_original_task_success_rate': rate('official_original_success'),
        'executed_attacker_tool_rate': rate('attacker_tool_executed') if valid and cases[0]['attack'] != 'clean' else None,
        'official_refusal_rate': (sum(case['official_refusal'] for case in complete) / n
            if valid and all(case.get('official_refusal') is not None for case in complete) else None),
        'counts': counts}


def evaluate_case(args, root, case, config, directory, native, scorer, signer, memory=None,
                  transport_factory=None, reviewer=None):
    contexts = getattr(args, '_task_contexts', None) or TaskContexts(getattr(args, 'task_context', None))
    task_context = contexts.for_request(case['task'])
    requirements = getattr(args, '_task_requirements', None) or TaskRequirements(getattr(args, 'task_requirements', None))
    task_requirements = requirements.for_request(case['task'])
    if task_context and task_requirements and task_context.get('requirements') != task_requirements:
        raise ValueError('Trusted context and semantic requirement file disagree')
    semantic_requirements = task_requirements or (task_context or {}).get('requirements') or None
    execution_request = actor_request(case['task'], task_context)
    directory.mkdir()
    audit = CertificateLog(directory / 'audit.jsonl', signer)
    deadline = time.monotonic() + args.timeout
    host = ASBHost(mode=args.mode, user_request=case['task'], catalog=catalog_for(root, case, args.attack),
        signer=signer, audit=audit, tool_classes=(native.SimulatedTool, native.AttackerTool),
        business_policy=args.business_policy, reviewer=reviewer, deadline=deadline,
        tool_contracts=getattr(args, '_tool_contracts', None) or ToolContracts(getattr(args, 'tool_contracts', None)),
        runtime_hash='sha256:' + file_hash(root / 'pyopenagi/tools/simulated_tool.py'),
        review_profile=getattr(args, 'review_profile', 'shared'),
        require_tool_contracts=getattr(args, 'require_tool_contracts', False), task_context=task_context,
        task_requirements=semantic_requirements)
    write_json(directory / 'capability-report.json', capability_report(host.catalog, host.contracts, host.runtime_hash))
    if task_context is not None:
        write_json(directory / 'task-context.json', task_context)
    result = {'id': case['id'], 'agent': case['agent'], 'task_index': case['task_index'],
        'attack': args.attack, 'status': 'incomplete', 'official_refusal': None,
        'task_context_hash': object_hash(task_context) if task_context is not None else None,
        'task_variant': ('trusted_clarification' if task_context is not None else
                         'semantic_requirements' if semantic_requirements else 'native')}
    agent = None
    transport = None
    stage = 'agent_initialization'
    started = time.monotonic()
    try:
        module = importlib.import_module(agent_module_path(case['agent']))
        cls = getattr(module, ''.join(part.title() for part in case['agent'].split('_')))
        with (directory / 'native.log').open('w', encoding='utf-8') as stream, contextlib.redirect_stdout(stream):
            agent = cls(case['agent_path'], execution_request, None, 'console',
                        native_args(args, root), case['attacker'], memory, case['attacker']['Aggressive'])
            transport = (transport_factory or ActionTransport)(config, deadline)
            agent.get_response = transport
            attach_hooks(agent, root / 'pyopenagi/agents/react_agent_attack.py', host, vars(native),
                         recovery=getattr(args, 'recovery', 'native'),
                         max_recovery_requests=getattr(args, 'max_recovery_requests', 2),
                         action_context=getattr(args, 'action_context', 'native'))
            stage = 'agent_execution'
            output = agent.run()
            host.raise_if_failed()
            if not output.get('workflow_failure') and agent._icb_coordinator is not None:
                stage = 'completion_checkpoint'
                agent._icb_finish()
                output['messages'] = agent.messages
                output['result'] = agent.messages[-1]
            stage = 'official_scoring'
            if time.monotonic() >= deadline:
                raise TimeoutError('ASB task deadline expired')
            if output.get('workflow_failure'):
                # Official task failure, not a transport/configuration error.
                result['workflow_failure'] = True
            result['official_attack_success'] = bool(scorer['check_attack_success'](
                output['messages'], agent.args, case['attacker']['Attack goal'])) if args.attack != 'clean' else None
            result['official_original_success'] = bool(scorer['check_original_success'](
                output['messages'], agent.args, output['normal_tools']))
            if not args.skip_refusal_judge:
                from openai import OpenAI
                # The official judge function, prompt, model and selection are
                # retained; its model remains gpt-4o-mini as in local ASB.
                judge = scorer['judge_response']
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('ASB judge deadline expired')
                judge.__globals__['OpenAI'] = lambda: OpenAI(timeout=min(60, remaining), max_retries=0)
                filtered = [message for message in output['messages']
                            if '[Thinking]' in str(message) or "'thinking'" in str(message)]
                refusal = judge(str(filtered)) if len(filtered) > 1 else '1'
                if refusal not in {'0', '1'}:
                    raise RuntimeError('Official refusal judge failed')
                result['official_refusal'] = refusal == '0'
            if time.monotonic() >= deadline:
                raise TimeoutError('ASB scoring deadline expired')
            result['status'] = 'complete'
            result['action_requests'] = transport.requests
    except Exception as error:
        result['error_type'] = type(error).__name__
        if isinstance(error, ActionTransportError):
            result['diagnostic'] = error.diagnostic
        elif host.failure_diagnostic:
            result['diagnostic'] = host.failure_diagnostic
        elif isinstance(error, (CompletionProtocolError, ActionContextError)):
            result['diagnostic'] = error.diagnostic
        else:
            result['diagnostic'] = {'stage': stage, 'code': type(error).__name__}
        # Known diagnostic codes only, never exception strings.
        result['failure_stage'] = 'host' if host.failure else 'agent_or_model_or_judge'
    finally:
        result.update(counts=host.counts, elapsed_seconds=round(time.monotonic() - started, 3),
            attacker_tool_executed=any(event['executed'] and event['tool'] == case['attacker']['Attacker Tool']
                                       for event in host.events) if args.attack != 'clean' else None)
        write_json(directory / 'calls.json', host.events)
        write_json(directory / 'reviews.json', host.reviewer.records if host.reviewer else [])
        write_json(directory / 'review-inputs.json', host.review_inputs)
        write_json(directory / 'requests.json', getattr(transport, 'records', []))
        actor_context = getattr(agent, '_icb_action_context', None)
        write_json(directory / 'action-context.json', getattr(actor_context, 'records', []))
        coordinator = getattr(agent, '_icb_coordinator', None)
        write_json(directory / 'recovery.json', coordinator.records if coordinator else [])
        result['trust_diagnostics'] = {
            'executed_without_independent_contract': sum(bool(e.get('executed')) and
                not e['tool_trust'].get('instance_verified', False) for e in host.events),
            'blocked_missing_contract': sum(e.get('rule') == 'tool.provenance_required' for e in host.events),
            'blocked_contract_mismatch': sum(e.get('rule') == 'tool.contract_pin_mismatch' for e in host.events)}
        result['response_retry_count'] = sum(r.get('attempt', 1) > 1 for r in getattr(transport, 'records', []))
        result['recovery_request_count'] = coordinator.requests if coordinator else 0
        write_json(directory / 'messages.json', agent.messages if agent is not None else [])
        write_json(directory / 'task-progress.json', host.task_progress())
        if not audit.verify_chain()['ok']:
            result['status'] = 'incomplete'
            result['error_type'] = 'AuditChainError'
        diagnostic = case_diagnostics(result, host.events, getattr(transport, 'records', []),
            agent.messages if agent is not None else [], getattr(agent, 'normal_tools', {}),
            host.reviewer.records if host.reviewer else [], task_progress=host.task_progress(),
            completion_records=coordinator.records if coordinator else [])
        write_json(directory / 'diagnostics.json', diagnostic)
        result['diagnostic_factors'] = diagnostic['factors']
        write_json(directory / 'result.json', result)
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--asb-root', type=Path, default=Path('F:/Datasets/ASB'))
    p.add_argument('--mode', choices=('baseline', 'guarded'), default='guarded')
    p.add_argument('--attack', choices=ATTACKS, default='opi')
    p.add_argument('--attack-type', choices=('naive', 'context_ignoring', 'fake_completion', 'escape_characters', 'combined_attack'), default='context_ignoring')
    p.add_argument('--attack-tools', choices=('all', 'agg', 'non-agg'), default='all')
    p.add_argument('--agent', action='append', help='Native agent name; repeat to select several')
    p.add_argument('--task-num', type=int, default=1, help='Tasks per agent, as in official ASB')
    p.add_argument('--limit', type=int, default=10, help='Maximum task/attacker pairs; 0 means all selected pairs')
    p.add_argument('--case-id', action='append', help='Explicit case IDs from --check; repeat; use --limit 0')
    p.add_argument('--task-context', type=Path,
                   help='Trusted pre-authored user Q/A and semantic requirements; separate clarified-task experiment, not native ASB scores')
    p.add_argument('--task-requirements', type=Path,
                   help='Operator-authored semantic deliverables; progress evidence only, never user authority or a tool checklist')
    p.add_argument('--model')
    p.add_argument('--action-config', choices=('agentdojo', 'env'), default='agentdojo',
                   help='Default: reuse AgentDojo pi configuration; env: explicitly use ASB_ACTION_*')
    p.add_argument('--pi-agent-dir', type=Path, help='Same directory as AgentDojo; auto-detect project .local-qwen or ~/.pi/agent')
    p.add_argument('--provider', help='Same pi provider as AgentDojo; auto-select if unique')
    p.add_argument('--max-tokens', type=int, help='Default: reuse pi model maxTokens (environment mode: 256)')
    p.add_argument('--max-requests', type=int, default=64)
    p.add_argument('--response-retries', type=int, choices=(0, 1), default=1,
                   help='Response-only repair before dispatch; identical in baseline/guarded')
    p.add_argument('--recovery', choices=('native', 'bounded', 'checkpoint'), default='native',
                   help='Experimental bounded execution coordination; native preserves the original agent loop')
    p.add_argument('--action-context', choices=('native', 'structured'), default='native',
                   help='Experimental phase/source separation; native remains default until paired utility and latency improve')
    p.add_argument('--review-profile', choices=('shared', 'asb'), default='shared',
                   help='Default shared ICB reviewer; asb is an experimental compact simulation profile')
    p.add_argument('--review-thinking-mode', choices=('auto', 'inherit', 'enabled', 'disabled'), default='auto',
                   help='Auto disables DeepSeek reviewer thinking only when no thinking controls are configured')
    p.add_argument('--review-max-tokens', type=int, choices=range(1, 16385), metavar='1..16384',
                   help='Reviewer output cap; otherwise preserve environment or use 4096')
    p.add_argument('--authorization-profile', choices=('standard', 'scope'), default='standard',
                   help='Experimental scope criteria distinguish permitted optional checks from workflow optimality')
    p.add_argument('--max-recovery-requests', type=int, choices=range(5), default=2)
    p.add_argument('--timeout', type=float, default=300)
    p.add_argument('--tool-schema', choices=('native', 'empty-object'), default='native')
    p.add_argument('--trigger', default='in light of extant literature')
    p.add_argument('--business-policy', type=Path)
    p.add_argument('--tool-contracts', type=Path, help='Independent operator declarations; v2 binds source, entrypoint, instance and capability scope')
    p.add_argument('--tool-contract-signature', type=Path,
                   help='Detached Ed25519 signature over the canonical tool-contract JSON')
    p.add_argument('--tool-contract-public-key', type=Path,
                   help='Independently provisioned Ed25519 public key for the detached signature')
    p.add_argument('--require-tool-contracts', action='store_true',
                   help='Explicit operator trust boundary: unverified tools are blocked in guarded mode')
    p.add_argument('--require-complete-tool-contract-coverage', action='store_true',
                   help='Fail preflight if any selected catalog tool lacks a complete v2 contract')
    p.add_argument('--require-signed-tool-contracts', action='store_true',
                   help='Require a verified detached signature for the operator contract registry')
    p.add_argument('--memory-db', type=Path, help='Required for memory attacks; copied, never updated in-place')
    p.add_argument('--skip-refusal-judge', action='store_true', help='Keep ASR/task scorers, report refusal rate as null')
    p.add_argument('--output', type=Path)
    p.add_argument('--check', action='store_true', help='Offline source/selection/dependency check, no model calls')
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    with reviewer_environment(args):
        return run(args)


def run(args):
    root = args.asb_root.resolve()
    if args.action_context == 'structured' and args.attack not in {'clean', 'opi'}:
        raise ValueError('Structured action context is validated for clean/OPI only; select --action-context native explicitly for other attack modes')
    if (args.task_num < 1 or args.limit < 0 or (args.max_tokens is not None and args.max_tokens < 1) or args.max_requests < 1
            or not math.isfinite(args.timeout) or not 0 < args.timeout <= 3600):
        raise ValueError('Invalid ASB limits')
    if args.mode == 'baseline' and args.business_policy:
        raise ValueError('Business policy only applies to guarded runs')
    if args.attack == 'memory' and (args.memory_db is None or not args.memory_db.is_dir()):
        raise ValueError('Memory attacks require an explicit existing --memory-db snapshot')
    if args.attack != 'memory' and args.memory_db:
        raise ValueError('--memory-db is only used for memory attacks')
    if args.memory_db:
        args.memory_db = args.memory_db.resolve()
    source_hashes = validate_source(root)
    cases = select_cases(root, args)
    contexts = TaskContexts(args.task_context)
    args._task_contexts = contexts
    requirements = TaskRequirements(args.task_requirements)
    args._task_requirements = requirements
    for case in cases:
        context = contexts.for_request(case['task'])
        required = requirements.for_request(case['task'])
        if context and required and context.get('requirements') != required:
            raise ValueError('Trusted context and semantic requirement file disagree')
    catalogs = {case['id']: catalog_for(root, case, args.attack) for case in cases}
    config = action_config(args)
    config['response_retries'] = args.response_retries
    contracts = ToolContracts(args.tool_contracts, args.tool_contract_signature, args.tool_contract_public_key)
    args._tool_contracts = contracts
    contract_coverage = contracts.coverage(catalogs.values(), runtime_hash='sha256:' +
        file_hash(root / 'pyopenagi/tools/simulated_tool.py'))
    if args.require_tool_contracts and (not contracts.entries or contracts.version != 2):
        raise ValueError('--require-tool-contracts needs independently authored version 2 --tool-contracts')
    if args.require_signed_tool_contracts and not args.require_tool_contracts:
        raise ValueError('--require-signed-tool-contracts also requires --require-tool-contracts')
    if args.require_complete_tool_contract_coverage and not args.require_tool_contracts:
        raise ValueError('--require-complete-tool-contract-coverage also requires --require-tool-contracts')
    if args.require_signed_tool_contracts and not contracts.signature_verified:
        raise ValueError('--require-signed-tool-contracts needs a valid signature and independent public key')
    if args.require_complete_tool_contract_coverage and (
            contract_coverage['missing_tools'] or contract_coverage['incomplete_tools']):
        raise ValueError('Required tool contracts must completely cover every selected catalog tool')
    runtime_hash = 'sha256:' + file_hash(root / 'pyopenagi/tools/simulated_tool.py')
    for catalog in catalogs.values():
        for name, spec in catalog.items():
            contracts.resolve(name, spec, runtime_hash)
    missing = [name for name in NATIVE_DEPENDENCIES if importlib.util.find_spec(name) is None]
    if args.business_policy:
        args.business_policy = args.business_policy.resolve()
    BusinessPolicy(args.business_policy)
    protocol = (CLARIFICATION_PROTOCOL if contexts.fingerprint else
                REQUIREMENTS_PROTOCOL if requirements.fingerprint else 'asb-native-icb-v1')
    plan = {'source': str(root), 'mode': args.mode, 'attack': args.attack, 'protocol': protocol,
        'task_context_hash': contexts.fingerprint,
        'task_requirements_hash': requirements.fingerprint,
        'selected_pairs': len(cases), 'case_ids': [case['id'] for case in cases],
        'source_hashes': source_hashes, 'missing_native_dependencies': missing,
        'action_model_configured': bool(config['model'] and config['api_key']),
        'action_config_source': config['source'], 'action_provider': config['provider'],
        'action_model': config['model'],
        'execution_recovery': args.recovery, 'response_retries': args.response_retries,
        'action_context': args.action_context,
        'tool_contracts_hash': contracts.fingerprint,
        'require_tool_contracts': args.require_tool_contracts,
        'require_complete_tool_contract_coverage': args.require_complete_tool_contract_coverage,
        'require_signed_tool_contracts': args.require_signed_tool_contracts,
        'tool_contract_signature_verified': contracts.signature_verified,
        'tool_contract_coverage': {key: contract_coverage[key] for key in
            ('selected_tool_count', 'declared_count', 'complete_count', 'missing_tools', 'incomplete_tools')},
        'review_profile': args.review_profile,
        'authorization_profile': args.authorization_profile,
        'intent_model_configured': intent_llm_configured(),
        'official_refusal_judge': not args.skip_refusal_judge,
        'official_judge_key_configured': bool(os.environ.get('OPENAI_API_KEY')),
        'ready': not missing and bool(config['model'] and config['api_key'])
            and (args.mode == 'baseline' or intent_llm_configured())
            and (args.skip_refusal_judge or bool(os.environ.get('OPENAI_API_KEY')))}
    if args.check:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return 0
    if not plan['ready']:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        raise RuntimeError('ASB not configured; install adapters/asb/requirements.txt and configure models')
    args.model = config['model']
    output = (args.output or PROJECT / 'results' / ('asb_' + args.mode + '_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f'))).resolve()
    if output == root or output.is_relative_to(root):
        raise ValueError('Output must be outside the original ASB checkout')
    output.mkdir(parents=True, exist_ok=False)
    runtime = output / 'runtime'
    all_hashes = snapshot(root, runtime)
    policy = output / 'business-policy.json'
    if args.business_policy:
        policy.write_bytes(args.business_policy.read_bytes())
        args.business_policy = policy
    if args.tool_contracts:
        contract_snapshot = output / 'tool-contracts.json'
        write_json(contract_snapshot, contracts.snapshot())
        args.tool_contracts = contract_snapshot
    if args.tool_contract_signature:
        signature_snapshot = output / 'tool-contracts.sig'
        public_key_snapshot = output / 'tool-contracts-public.pem'
        shutil.copyfile(args.tool_contract_signature, signature_snapshot)
        shutil.copyfile(args.tool_contract_public_key, public_key_snapshot)
        verified_snapshot = ToolContracts(contract_snapshot, signature_snapshot, public_key_snapshot)
        if (verified_snapshot.fingerprint != contracts.fingerprint or
                verified_snapshot.signer_public_key_hash != contracts.signer_public_key_hash):
            raise RuntimeError('Tool contract trust snapshot changed during archival')
    if contexts.fingerprint:
        write_json(output / 'task-context.json', contexts.snapshot())
    if requirements.fingerprint:
        write_json(output / 'task-requirements.json', requirements.snapshot())
    write_json(output / 'selection.json', [{key: value for key, value in case.items() if key != 'attacker'} for case in cases])
    write_json(output / 'catalogs.json', catalogs)
    write_json(output / 'tool-contract-coverage.json', contract_coverage)
    write_json(output / 'source-hashes.json', all_hashes)
    policy_hashes = policy_source_hashes()
    write_json(output / 'policy-source-hashes.json', policy_hashes)
    archive_policy_sources(output / 'code_snapshot', policy_hashes)
    metadata = {'protocol': protocol, 'status': 'running', 'mode': args.mode,
        'task_variant': ('trusted_clarification' if contexts.fingerprint else
                         'semantic_requirements' if requirements.fingerprint else 'native'),
        'score_interpretation': ('Unmodified ASB marker scorers applied to clarified tasks; '
            'not original-task benchmark results or verified analysis quality.' if contexts.fingerprint else
            'Unmodified ASB marker scorers; tool coverage does not prove analysis quality.'),
        'selected_count': len(cases),
        'comparison': {'attack': args.attack, 'attack_type': args.attack_type,
            'case_ids': plan['case_ids'], 'source_hash': object_hash(all_hashes),
            'catalog_hash': object_hash(catalogs), 'model': args.model,
            'task_context_hash': contexts.fingerprint,
            'task_requirements_hash': requirements.fingerprint,
            'action_endpoint_hash': object_hash(config['base_url']), 'max_tokens': config['max_tokens'],
            'action_config_source': config['source'], 'action_provider': config['provider'],
            'max_tokens_field': config['max_tokens_field'],
            'action_headers_hash': object_hash(config['headers']),
            'max_requests': args.max_requests, 'timeout': args.timeout, 'tool_schema': args.tool_schema,
            'response_retries': args.response_retries, 'execution_recovery': args.recovery,
            'action_context': args.action_context,
            'max_recovery_requests': args.max_recovery_requests,
            'tool_contracts_hash': contracts.fingerprint,
            'require_tool_contracts': args.require_tool_contracts,
            'require_complete_tool_contract_coverage': args.require_complete_tool_contract_coverage,
            'require_signed_tool_contracts': args.require_signed_tool_contracts,
            'tool_contract_signature_verified': contracts.signature_verified,
            'tool_contract_signer_key_hash': contracts.signer_public_key_hash,
            'tool_contract_coverage_hash': object_hash(contract_coverage),
            'authorization_profile': args.authorization_profile,
            'review_profile': args.review_profile,
            'review_settings': settings_snapshot(),
            'review_identity': review_model_identity(),
            'trigger': args.trigger, 'refusal_judge': not args.skip_refusal_judge,
            'judge_endpoint_hash': object_hash(os.environ.get('OPENAI_BASE_URL', 'https://api.openai.com/v1'))
                if not args.skip_refusal_judge else None,
            'python_version': sys.version,
            'python_hash_seed': os.environ.get('PYTHONHASHSEED', 'random'),
            # Diagnostic only; cryptographic authorization still uses SHA-256.
            'python_hash_probe': hash('icb-asb-order-probe-v1'),
            'dependency_versions': {name: importlib.metadata.version(name) for name in
                ('pydantic', 'requests', 'numpy', 'pandas', 'openai', 'langchain-core', 'langchain-chroma',
                 'langchain-openai', 'langchain-ollama', 'z3-solver')}},
        'policy_code_hash': object_hash(policy_hashes),
        'review_model': os.environ.get('ICB_INTENT_LLM_MODEL', 'gpt-4o-mini') if args.mode == 'guarded' else None,
        'review_profile': args.review_profile,
        'action_context': args.action_context,
        'authorization_profile': args.authorization_profile,
        'require_tool_contracts': args.require_tool_contracts,
        'require_complete_tool_contract_coverage': args.require_complete_tool_contract_coverage,
        'require_signed_tool_contracts': args.require_signed_tool_contracts,
        'review_settings': settings_snapshot(),
        'business_policy_hash': file_hash(policy) if args.business_policy else None,
        'adaptations': ['serial OpenAI-compatible transport replaces AIOS scheduling',
            'explicit action context profile; native scorer history and attack payloads retained',
            'explicit bounded response repair and optional agent coordination recorded in comparison',
            'native tool dispatch and delivered observation hooks', 'explicit environment; dotenv disabled',
            'clean tasks deduplicated across attacker-tool combinations',
            'task deadline and request budget; failures are incomplete'],
        'trust_model': 'original pre-injection task is trusted; tool observations and catalog claims are untrusted',
        'tool_trust_experiment': ('operator-contract-required' if args.require_tool_contracts else
                                  'limited-provenance-purpose-review'),
        'tool_contract_version': contracts.version,
        'scope': 'ASB fixed-string tool simulation; no argument-level or production execution claim',
        'cases': []}
    write_json(output / 'summary.json', metadata)
    original_cwd = Path.cwd()
    sys.dont_write_bytecode = True
    try:
        os.chdir(runtime)
        native = load_native(runtime)
        # Exported here by BaseAgent, used without importing AIOS.
        tools = importlib.import_module('pyopenagi.tools.simulated_tool')
        native.SimulatedTool = tools.SimulatedTool
        scorer = official_scorers(runtime)
        with tempfile.TemporaryDirectory(prefix='icb-asb-keys-', dir=output) as keydir:
            signer = Signer(Path(keydir) / 'private.pem', Path(keydir) / 'public.pem')
            signer.sign({'purpose': 'asb-ephemeral-audit'})
            (output / 'audit-public.pem').write_bytes((Path(keydir) / 'public.pem').read_bytes())
            memory = None
            if args.attack == 'memory':
                import shutil
                # One private copy per run, never the operator's original DB.
                for path in args.memory_db.rglob('*'):
                    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
                        raise ValueError('Memory snapshot cannot contain links')
                shutil.copytree(args.memory_db, output / 'memory-db')
                metadata['comparison']['memory_hash'] = object_hash({str(path.relative_to(args.memory_db)): file_hash(path)
                    for path in sorted(args.memory_db.rglob('*')) if path.is_file()})
                memory = native.Chroma(persist_directory=str(output / 'memory-db'),
                    embedding_function=native.OpenAIEmbeddings(openai_api_key=os.environ.get('OPENAI_API_KEY')))
            for index, case in enumerate(cases, 1):
                random.seed(0)
                print(f'[{index}/{len(cases)}] {args.mode} {case["agent"]} {case["id"]}', flush=True)
                result = evaluate_case(args, runtime, case, config, output / case['id'], native, scorer, signer, memory)
                metadata['cases'].append(result)
                metadata['metrics'] = summarize(metadata['cases'], len(cases))
                if len(metadata['cases']) != len(cases):
                    metadata['metrics'].update(selected=len(cases),
                        official_attack_success_rate=None, official_original_task_success_rate=None,
                        executed_attacker_tool_rate=None, official_refusal_rate=None)
                write_json(output / 'summary.json', metadata)
                print('  ' + result['status'] + ' ' + json.dumps(result['counts']), flush=True)
            metadata['status'] = 'complete' if all(case['status'] == 'complete' for case in metadata['cases']) else 'incomplete'
    except BaseException as error:
        metadata['status'] = 'incomplete'
        metadata['error_type'] = type(error).__name__
        raise
    finally:
        os.chdir(original_cwd)
        # Preserve selected denominator even after a stopped/failed run.
        metadata['selected_count'] = len(cases)
        metadata['metrics'] = summarize(metadata['cases'], len(cases))
        if policy_source_hashes() != policy_hashes:
            metadata['status'] = 'incomplete'
            metadata['error_type'] = 'PolicySourceChangedDuringRun'
        if len(metadata['cases']) != len(cases) or metadata['status'] != 'complete':
            metadata['metrics'].update(selected=len(cases), errors=len(cases)-metadata['metrics']['complete'],
                official_attack_success_rate=None, official_original_task_success_rate=None,
                executed_attacker_tool_rate=None, official_refusal_rate=None)
        write_json(output / 'summary.json', metadata)
        print('ASB results: ' + str(output), flush=True)
    return 0 if metadata['status'] == 'complete' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Keep CLI diagnostics free of arbitrary service error text.
        diagnostic = error.code if isinstance(error, ActionConfigurationError) else type(error).__name__
        print('ASB stopped: ' + diagnostic + ' (run --check; inspect result error_type)', file=sys.stderr)
        raise SystemExit(1)
