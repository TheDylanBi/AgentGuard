"""Full clean-set accounting and reviewed manifest coverage; no model calls."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentdojo.task_suite import get_suites
from agentdojo.functions_runtime import FunctionsRuntime
from adapters.agentdojo_pi.host import load_manifest, SimulationHost, PROJECT
from adapters.agentdojo_pi.run_all import aggregate, main
from attestation.signer import Signer
from attestation.log import CertificateLog


class AllSuitesTests(unittest.TestCase):
    def test_exact_local_v122_inventory_and_pinned_manifests(self):
        suites = get_suites('v1.2.2')
        self.assertEqual({k:len(v.user_tasks) for k,v in suites.items()},
                         {'workspace':40,'travel':20,'banking':16,'slack':21})
        for name, suite in suites.items():
            runtime = FunctionsRuntime(suite.tools)
            data = load_manifest(PROJECT/'adapters/agentdojo_pi'/f'{name}_manifest.json', runtime)
            self.assertEqual(data['suite'], name)
            self.assertEqual(set(data['tools']), set(runtime.functions))
            self.assertTrue(all(row.get('schema_hash') for row in data['tools'].values()))

    def test_shared_tools_require_exact_schema_not_name_alone(self):
        suites = get_suites('v1.2.2')
        root = PROJECT/'adapters/agentdojo_pi'
        w = load_manifest(root/'workspace_manifest.json', FunctionsRuntime(suites['workspace'].tools))
        t = load_manifest(root/'travel_manifest.json', FunctionsRuntime(suites['travel'].tools))
        self.assertEqual(t['tools']['create_calendar_event']['schema_hash'],
                         w['tools']['create_calendar_event']['schema_hash'])
        self.assertNotIn('selected_file_read', t.get('bindings', {}))

    def test_partial_aggregate_does_not_treat_missing_tasks_as_scored(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'workspace').mkdir()
            (root/'workspace'/'summary.json').write_text(json.dumps({
                'status':'completed_with_errors', 'task_accounting':{'processed':40},
                'task_errors':[{}], 'official_results':{'utility_results':[{'value':True}]*24 + [{'value':False}]*15}}))
            result = aggregate({'benchmark_version':'v1.2.2','suites':{'workspace':40,'travel':20,'banking':16,'slack':21}},root)
            self.assertEqual(result['status'],'incomplete')
            self.assertEqual((result['successful'],result['scored'],result['errors'],result['remaining']), (24,39,1,57))
            self.assertAlmostEqual(result['success_per_planned'],24/97)
            self.assertIsNone(result['attack_success_rate'])

    def test_check_visits_every_suite_without_running_model(self):
        calls=[]
        def run(args):
            calls.append(args)
            self.assertIn('--check',args)
            return 0
        with patch('adapters.agentdojo_pi.run_all.run_suite', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--mode','guarded','--check']),0)
        self.assertEqual(len(calls),4)

    def test_all_suites_rejects_attack_and_task_filters(self):
        for flag in ['--attack=x','--user-task','--suite','--manifest']:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['--mode','guarded',flag])

    def test_financial_envelope_not_relabelled_as_read(self):
        suite = get_suites('v1.2.2')['banking'];runtime=FunctionsRuntime(suite.tools)
        data=load_manifest(PROJECT/'adapters/agentdojo_pi/banking_manifest.json',runtime)
        for name in ['send_money','schedule_transaction','update_scheduled_transaction']:
            self.assertEqual(data['tools'][name]['capability']['effect_type'],'financial_transfer')
            self.assertIn('financial_transfer',data['tools'][name]['semantic_action']['effects'])

    def test_full_orchestration_accounts_all_97_and_keeps_model_errors(self):
        suites=get_suites('v1.2.2')
        def fake(args):
            if '--check' in args:
                return 0
            name=args[args.index('--suite')+1];count=len(suites[name].user_tasks)
            folder=Path(args[args.index('--output')+1]);folder.mkdir()
            error_count=1 if name=='banking' else 0
            (folder/'summary.json').write_text(json.dumps({'status':'completed_with_errors' if error_count else 'completed',
                'task_accounting':{'processed':count},'task_errors':[{}]*error_count,
                'official_results':{'utility_results':[{'value':True}]*(count-error_count)}}))
            return 0
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'all'
            with patch('adapters.agentdojo_pi.run_all.run_suite',side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['--mode','baseline','--output',str(output)]),0)
            result=json.loads((output/'summary.json').read_text())
            self.assertEqual((result['planned'],result['processed'],result['scored'],result['errors']), (97,97,96,1))
            self.assertEqual(result['status'],'completed_with_errors')
            self.assertEqual(result['remaining'],0)

    def test_interrupt_saves_partial_global_summary(self):
        def fake(args):
            if '--check' in args:
                return 0
            raise KeyboardInterrupt()
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'all'
            with patch('adapters.agentdojo_pi.run_all.run_suite',side_effect=fake), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(KeyboardInterrupt):
                main(['--mode','baseline','--output',str(output)])
            result=json.loads((output/'summary.json').read_text())
            self.assertEqual(result['status'],'incomplete')
            self.assertEqual(result['remaining'],97)

    def test_real_read_execution_in_each_new_suite_is_available(self):
        examples={'travel':('get_user_information',{}),'banking':('get_balance',{}),'slack':('get_channels',{})}
        suites=get_suites('v1.2.2')
        for name,(tool,args) in examples.items():
            with self.subTest(suite=name), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);suite=suites[name];runtime=FunctionsRuntime(suite.tools)
                manifest=load_manifest(PROJECT/'adapters/agentdojo_pi'/f'{name}_manifest.json',runtime)
                signer=Signer(root/'private',root/'public');audit=CertificateLog(root/'audit.jsonl',signer=signer)
                host=SimulationHost(runtime,suite.load_and_inject_default_environment({}),manifest,signer,audit,mode='baseline')
                self.assertIsNone(host.call('read',tool,args)[1])
                self.assertEqual(host.counts['executed'],1)


if __name__ == '__main__':
    unittest.main()
