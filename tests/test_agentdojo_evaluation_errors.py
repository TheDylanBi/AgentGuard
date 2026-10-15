import copy
import json
import tempfile
import unittest
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agentdojo.logging import OutputLogger
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from policy.intent_output import IntentStageError
from adapters.agentdojo_pi.errors import ActionModelError
from adapters.agentdojo_pi.evaluation import benchmark_with_task_errors, ConsecutiveTaskErrors
from adapters.agentdojo_pi.run import record_results, main
from tests.test_agentdojo_pi import PI, NODE


def failure():
    return IntentStageError({"stage": "rules", "status": "invalid_output", "output_error": "invalid_json_syntax"})


class EvaluationErrorTests(unittest.TestCase):
    def test_truncated_action_is_unscored_and_other_task_continues(self):
        def run(pipeline, task, *args, **kwargs):
            if task.ID == "user_task_0":
                raise ActionModelError({"stage": "action", "status": "truncated_output"})
            return True, False
        suite, _, pipeline = self.fixture(run)
        updates = []
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder):
            result = benchmark_with_task_errors(pipeline, suite,
                on_update=lambda state: updates.append(copy.deepcopy(state)))
        self.assertEqual(len(result["utility_results"]), 1)
        error = updates[-1]["task_errors"][0]
        self.assertEqual(error["action_diagnostic"]["status"], "truncated_output")
        self.assertNotIn("intent_diagnostic", error)
        self.assertIsNone(updates[-1]["task_outcomes"][0]["utility"])

    def fixture(self, behavior=None, count=2):
        users = {f"user_task_{i}": SimpleNamespace(ID=f"user_task_{i}") for i in range(count)}
        injections = {f"injection_task_{i}": SimpleNamespace(ID=f"injection_task_{i}") for i in range(count)}
        suite = SimpleNamespace(name="fixture", user_tasks=users, injection_tasks=injections,
            get_user_task_by_id=lambda key: users[key], get_injection_task_by_id=lambda key: injections[key],
            run_task_with_pipeline=behavior or (lambda *a, **k: (True, False)))
        attack = SimpleNamespace(name="fixture", is_dos_attack=False, attack=lambda *a: {})
        return suite, attack, SimpleNamespace(name="fixture", runs=[])

    def test_results_equal_official_when_no_errors(self):
        suite, attack, pipeline = self.fixture()
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder):
            for selected_attack in (None, attack):
                expected = (benchmark_suite_with_injections(pipeline, suite, attack, logdir=None, force_rerun=True)
                            if selected_attack else benchmark_suite_without_injections(pipeline, suite, logdir=None, force_rerun=True))
                actual = benchmark_with_task_errors(pipeline, suite, attack=selected_attack)
                self.assertEqual(actual, expected)

    def test_prescreen_error_retained_separately_and_pairs_still_scored(self):
        def run(pipeline, task, *args, **kwargs):
            if task.ID == "injection_task_0":
                raise failure()
            return True, False
        suite, attack, pipeline = self.fixture(run)
        updates = []
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            result = benchmark_with_task_errors(pipeline, suite, attack=attack,
                on_update=lambda state: updates.append(copy.deepcopy(state)))
        self.assertEqual(len(result["utility_results"]), 4)
        self.assertNotIn("injection_task_0", result["injection_tasks_utility_results"])
        self.assertEqual(len(updates[-1]["task_outcomes"]), 6)
        self.assertIsNone(updates[-1]["task_outcomes"][0]["security"])
        metadata = {}
        record_results(metadata, result, [], has_attack=True, state=updates[-1])
        self.assertEqual(metadata["status"], "completed_with_errors")
        self.assertEqual(metadata["task_accounting"]["errors"], 1)
        self.assertIsNone(metadata["metrics"]["attack_success_rate"])
        self.assertIsNone(metadata["metrics"]["utility_results"]["rate"])
        self.assertEqual(metadata["metrics"]["utility_results"]["scored_rate"], 1.0)

    def test_consecutive_errors_persist_before_stopping(self):
        def run(*a, **k):
            raise failure()
        suite, _, pipeline = self.fixture(run, count=5)
        updates = []
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder):
            with self.assertRaises(ConsecutiveTaskErrors):
                benchmark_with_task_errors(pipeline, suite, on_update=lambda state: updates.append(copy.deepcopy(state)))
        self.assertEqual(len(updates[-1]["task_errors"]), 3)
        self.assertEqual(updates[-1]["result"]["utility_results"], {})

    def test_unknown_error_and_keyboard_interrupt_are_not_swallowed(self):
        for error in (RuntimeError("bridge invariant"), KeyboardInterrupt()):
            def run(*a, **k):
                raise error
            suite, _, pipeline = self.fixture(run)
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as folder, OutputLogger(folder):
                with self.assertRaises(type(error)):
                    benchmark_with_task_errors(pipeline, suite)

    @unittest.skipUnless(PI.exists(), "Installed pi SDK required for CLI validation")
    def test_cli_partial_summary_survives_interrupt(self):
        pipeline = SimpleNamespace(name="fixture", runs=[], last_intent_diagnostic=None)
        with tempfile.TemporaryDirectory() as folder, \
             patch("adapters.agentdojo_pi.pipeline.PiPipeline", return_value=pipeline), \
             patch("agentdojo.benchmark.run_task_without_injection_tasks", side_effect=[(True, False), KeyboardInterrupt()]):
            output = Path(folder) / "run"
            with self.assertRaises(KeyboardInterrupt):
                main(["--mode", "baseline", "--provider", "fixture", "--model", "fixture", "--node", NODE,
                      "--pi-package", str(PI), "--user-task", "user_task_0", "--user-task", "user_task_1",
                      "--continue-on-error", "--no-progress", "--output", str(output)])
            data = json.loads((output / "summary.json").read_text())
            self.assertEqual(data["status"], "incomplete")
            self.assertEqual(data["task_accounting"]["remaining"], 1)
            self.assertEqual(len(data["official_results"]["utility_results"]), 1)
            self.assertEqual(data["interrupted_task"]["user_task"], "user_task_1")
            self.assertIsNone(data["metrics"]["utility_results"]["rate"])
