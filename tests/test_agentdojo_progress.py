import io
import tempfile
import unittest
from types import SimpleNamespace

import agentdojo.benchmark as benchmark
from agentdojo.logging import OutputLogger
from rich.console import Console
from adapters.agentdojo_pi.progress import task_progress, report_activity, report_task_error


class ProgressTests(unittest.TestCase):
    def exercise(self, attack=None, interrupted=False, enabled=True, delayed=False):
        output = io.StringIO()
        console = Console(file=output, force_terminal=False, width=160)
        suite = SimpleNamespace(user_tasks={"user_task_0": None}, injection_tasks={"injection_task_0": None})
        original = benchmark.TraceLogger
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder) as delegate:
            try:
                with task_progress(suite, attack=attack, enabled=enabled, console=console):
                    cases = [("user_task_0", None)] if attack is None else (
                        [] if attack.is_dos_attack else [("injection_task_0", None)]) + [("user_task_0", "injection_task_0")]
                    for user, injection in cases:
                        with benchmark.TraceLogger(delegate=delegate, suite_name="workspace", user_task_id=user,
                                injection_task_id=injection, attack_type="fixture" if injection else "none",
                                pipeline_name="fixture") as logger:
                            if interrupted:
                                raise KeyboardInterrupt()
                            if not delayed:
                                logger.set_contextarg("utility", False)
                                logger.set_contextarg("security", False)
                        if delayed:
                            logger.set_contextarg("utility", True)
                            logger.set_contextarg("security", False)
                            logger.set_contextarg("duration", 1)  # must not count twice
            except KeyboardInterrupt:
                pass
        self.assertIs(benchmark.TraceLogger, original)
        return output.getvalue()

    def test_clean_counts_failed_utility_as_scored(self):
        self.assertIn("1/1 scored user_task_0", self.exercise())

    def test_attack_separates_prescreen_and_pairs(self):
        text = self.exercise(SimpleNamespace(is_dos_attack=False))
        self.assertIn("Attack-goal prescreen: 1/1 scored injection_task_0", text)
        self.assertIn("Attack pairs: 1/1 scored user_task_0/injection_task_0", text)

    def test_dos_does_not_expect_prescreen(self):
        text = self.exercise(SimpleNamespace(is_dos_attack=True))
        self.assertNotIn("prescreen", text)
        self.assertIn("Attack pairs: 1/1 scored", text)

    def test_interrupt_does_not_increment_and_restores_logger(self):
        text = self.exercise(interrupted=True)
        self.assertIn("0/1 interrupted user_task_0", text)
        self.assertNotIn("1/1 scored", text)

    def test_disabled_is_silent(self):
        self.assertEqual(self.exercise(enabled=False), "")

    def test_attack_scores_after_context_exit_count_once(self):
        text = self.exercise(SimpleNamespace(is_dos_attack=False), delayed=True)
        self.assertIn("Attack pairs: 1/1 scored user_task_0/injection_task_0", text)
        self.assertNotIn("interrupted", text)
        self.assertNotIn("2/1", text)

    def test_official_attack_entry_counts_actual_scoring_order(self):
        user = SimpleNamespace(ID="user_task_0")
        injection = SimpleNamespace(ID="injection_task_0")
        suite = SimpleNamespace(name="fixture", user_tasks={user.ID: user},
            injection_tasks={injection.ID: injection}, get_user_task_by_id=lambda _: user,
            get_injection_task_by_id=lambda _: injection,
            run_task_with_pipeline=lambda *a, **k: (True, False))
        attack = SimpleNamespace(name="fixture", is_dos_attack=False, attack=lambda *a: {})
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder), task_progress(
                suite, attack=attack, console=Console(file=output, force_terminal=False, width=160)):
            result = benchmark.benchmark_suite_with_injections(SimpleNamespace(name="fixture"), suite,
                attack, logdir=None, force_rerun=True, benchmark_version="v1.2.2")
        self.assertEqual(result["utility_results"], {(user.ID, injection.ID): True})
        self.assertIn("Attack pairs: 1/1 scored", output.getvalue())
        self.assertNotIn("interrupted", output.getvalue())

    def test_activity_visible_before_task_finishes_and_does_not_increment_count(self):
        output = io.StringIO()
        suite = SimpleNamespace(user_tasks={"user_task_0": None}, injection_tasks={})
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder) as delegate:
            with task_progress(suite, console=Console(file=output, force_terminal=False, width=160)):
                with benchmark.TraceLogger(delegate=delegate, suite_name="fixture", user_task_id="user_task_0",
                        injection_task_id=None, attack_type="none", pipeline_name="fixture") as logger:
                    report_activity("intent: rules (waiting for model)")
                    self.assertIn("intent: rules", output.getvalue())
                    self.assertNotIn("1/1 scored", output.getvalue())
                    report_activity("agent: waiting for reply 2")
                    self.assertIn("waiting for reply 2", output.getvalue())
                    logger.set_contextarg("utility", True)
                    logger.set_contextarg("security", False)
        self.assertIn("1/1 scored", output.getvalue())
        before = output.getvalue()
        report_activity("outside run")
        self.assertEqual(output.getvalue(), before)

    def test_terminal_refreshes_activity_immediately(self):
        output = io.StringIO()
        suite = SimpleNamespace(user_tasks={"user_task_0": None}, injection_tasks={})
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder) as delegate:
            with task_progress(suite, console=Console(file=output, force_terminal=True, force_interactive=True, _environ={"TERM": "xterm"}, width=200)):
                with benchmark.TraceLogger(delegate=delegate, suite_name="fixture", user_task_id="user_task_0",
                        injection_task_id=None, attack_type="none", pipeline_name="fixture") as logger:
                    report_activity("waiting for reply 2")
                    self.assertIn("waiting for reply 2", output.getvalue())
                    logger.set_contextarg("utility", True)
                    logger.set_contextarg("security", False)

    def test_dumb_terminal_receives_live_text_updates(self):
        output = io.StringIO()
        suite = SimpleNamespace(user_tasks={"user_task_0": None}, injection_tasks={})
        console = Console(file=output, force_terminal=True, _environ={"TERM": "dumb"}, width=160)
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder) as delegate:
            with task_progress(suite, console=console):
                with benchmark.TraceLogger(delegate=delegate, suite_name="fixture", user_task_id="user_task_0",
                        injection_task_id=None, attack_type="none", pipeline_name="fixture") as logger:
                    report_activity("intent: rules")
                    self.assertIn("intent: rules", output.getvalue())
                    logger.set_contextarg("utility", True)
                    logger.set_contextarg("security", False)

    def test_multi_task_intermediate_count_visible_before_run_ends(self):
        output = io.StringIO()
        suite = SimpleNamespace(user_tasks={"user_task_0": None, "user_task_1": None}, injection_tasks={})
        with tempfile.TemporaryDirectory() as folder, OutputLogger(folder) as delegate:
            with task_progress(suite, console=Console(file=output, force_terminal=False, width=160)):
                for index in range(2):
                    with benchmark.TraceLogger(delegate=delegate, suite_name="fixture", user_task_id=f"user_task_{index}",
                            injection_task_id=None, attack_type="none", pipeline_name="fixture") as logger:
                        logger.set_contextarg("utility", True)
                        logger.set_contextarg("security", False)
                    self.assertIn(f"{index + 1}/2 scored", output.getvalue())
                    if index == 0:
                        self.assertNotIn("2/2 scored", output.getvalue())

    def test_handled_task_error_advances_processed_count_but_is_not_scored(self):
        output = io.StringIO()
        suite = SimpleNamespace(user_tasks={"user_task_0": None, "user_task_1": None}, injection_tasks={})
        with task_progress(suite, console=Console(file=output, force_terminal=False, width=160)):
            report_task_error("clean", "user_task_0")
            self.assertIn("1/2 error (not scored) user_task_0", output.getvalue())
            self.assertNotIn("1/2 scored", output.getvalue())
        before = output.getvalue()
        report_task_error("clean", "outside")
        self.assertEqual(output.getvalue(), before)
