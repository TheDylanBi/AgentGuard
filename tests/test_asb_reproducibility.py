"""Native set rendering must be reproducible across fresh interpreters."""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from adapters.asb.compare import compare

ASB = Path('F:/Datasets/ASB')


class OrderingTests(unittest.TestCase):
    @unittest.skipUnless(ASB.is_dir(), 'Native ASB checkout unavailable')
    def test_fixed_seed_preserves_native_workflow_tool_order_across_processes(self):
        source = r'''
import ast,json,types
from pathlib import Path
path=Path('F:/Datasets/ASB/pyopenagi/agents/react_agent_attack.py')
tree=ast.parse(path.read_text(encoding='utf-8-sig'))
cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ReactAgentAttack')
method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='attacker_tool_injection')
ns={}
exec(compile(ast.Module(body=[method],type_ignores=[]),str(path),'exec'),ns)
workflow=[{'message':'retrieve inputs','tool_use':['alpha','beta']},{'message':'compare','tool_use':['beta']}]
result=ns['attacker_tool_injection'](types.SimpleNamespace(tool_name='extension'),workflow)
print(json.dumps({'probe':hash('icb-asb-order-probe-v1'),'workflow':result}))
'''
        results = []
        for _ in range(2):
            process = subprocess.run([sys.executable, '-X', 'utf8', '-B', '-c', source],
                env={**os.environ, 'PYTHONHASHSEED': '0'}, capture_output=True, text=True, check=True)
            results.append(json.loads(process.stdout))
        self.assertEqual(results[0], results[1])
        self.assertEqual(set(results[0]['workflow'][0]['tool_use']), {'alpha', 'beta', 'extension'})

    def test_hash_probe_drift_is_explained_before_computing_effectiveness(self):
        first = {'mode': 'baseline', 'comparison': {'python_hash_seed': '0', 'python_hash_probe': 1}}
        second = {'mode': 'guarded', 'comparison': {'python_hash_seed': '0', 'python_hash_probe': 2}}
        with self.assertRaisesRegex(ValueError, 'PYTHONHASHSEED'): compare(first, second)


if __name__ == '__main__': unittest.main()
