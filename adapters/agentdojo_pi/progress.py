"""Observe official task traces without changing scheduling or scoring."""
from contextlib import contextmanager
from contextvars import ContextVar
from unittest.mock import patch

from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn, SpinnerColumn


_ACTIVITY = ContextVar("agentdojo_progress_activity", default=None)
_TASK_ERROR = ContextVar("agentdojo_progress_task_error", default=None)


def report_activity(stage):
    """Display trusted lifecycle labels only, never prompts, outputs or credentials."""
    callback = _ACTIVITY.get()
    if callback is not None:
        callback(stage)


def report_task_error(phase, label):
    callback = _TASK_ERROR.get()
    if callback is not None:
        callback(phase, label)


@contextmanager
def task_progress(suite, user_tasks=None, injection_tasks=None, attack=None, *, enabled=True, console=None):
    if not enabled:
        yield
        return
    import agentdojo.benchmark as benchmark

    users = len(user_tasks) if user_tasks is not None else len(suite.user_tasks)
    injections = len(set(injection_tasks)) if injection_tasks is not None else len(suite.injection_tasks)
    totals = {"clean": users} if attack is None else (
        {"attack": users} if attack.is_dos_attack else
        {"prescreen": injections, "attack": users * (len(injection_tasks) if injection_tasks is not None else injections)})
    labels = {"clean": "User tasks", "prescreen": "Attack-goal prescreen", "attack": "Attack pairs"}
    console = console or Console(stderr=True)
    bar = Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(),
                   TextColumn("{task.completed}/{task.total}"), TimeElapsedColumn(),
                   TextColumn("{task.fields[activity]}"), TextColumn("errors={task.fields[errors]}"), console=console, refresh_per_second=4)
    rows = {phase: bar.add_task(label, total=totals[phase], activity="waiting", errors=0, start=False)
            for phase, label in labels.items() if phase in totals}
    active = [None]
    def activity(stage):
        phase = active[0]
        if phase is None:
            return
        bar.update(rows[phase], activity=stage, refresh=True)
        if not console.is_interactive:
            console.print(f"{labels[phase]}: {stage}", markup=False)
            console.file.flush()

    def task_error(phase, label):
        row = rows[phase]
        bar.update(row, advance=1, errors=bar.tasks[row].fields["errors"] + 1,
                   description=labels[phase] + " | " + label,
                   activity="error (not scored)", refresh=True)
        if bar.tasks[row].finished:
            bar.stop_task(row)
        if not console.is_interactive:
            task = bar.tasks[row]
            console.print(f"{labels[phase]}: {int(task.completed)}/{int(task.total)} error (not scored) {label}", markup=False)
            console.file.flush()

    original = benchmark.TraceLogger

    class ProgressTrace(original):
        def __enter__(self):
            result = super().__enter__()
            self.progress_reported = False
            self.progress_failed = False
            self.progress_phase = ("attack" if self.context.get("injection_task_id") is not None else
                                   "prescreen" if attack is not None else "clean")
            self.progress_label = str(self.context.get("user_task_id", "unknown"))
            if self.context.get("injection_task_id") is not None:
                self.progress_label += "/" + str(self.context["injection_task_id"])
            phase = self.progress_phase
            active[0] = phase
            bar.start_task(rows[phase])
            bar.update(rows[phase], description=labels[phase] + " | " + self.progress_label,
                       activity="starting", refresh=True)
            if not console.is_interactive:
                console.print(f"{labels[phase]}: start {self.progress_label}", markup=False)
            return result

        def set_contextarg(self, key, value):
            super().set_contextarg(key, value)
            # Official clean scoring occurs inside the context; attack scoring
            # occurs AFTER __exit__. Observe the scores rather than exit timing.
            if (hasattr(self, "progress_reported") and not self.progress_failed
                    and "utility" in self.context and "security" in self.context):
                self._report(True)

        def __exit__(self, exc_type, exc_value, traceback):
            self.progress_failed = exc_type is not None
            result = super().__exit__(exc_type, exc_value, traceback)
            if self.progress_failed:
                self._report(False)
            return result

        def _report(self, scored):
            if self.progress_reported:
                return
            self.progress_reported = True
            phase = self.progress_phase
            bar.update(rows[phase], advance=int(scored), activity="scored" if scored else "interrupted", refresh=True)
            active[0] = None
            if bar.tasks[rows[phase]].finished:
                bar.stop_task(rows[phase])
            if not scored:
                bar.update(rows[phase], description=labels[phase] + " | interrupted " + self.progress_label, refresh=True)
            if not console.is_interactive:
                task = bar.tasks[rows[phase]]
                console.print(f"{labels[phase]}: {int(task.completed)}/{int(task.total)} "
                              f"{'scored' if scored else 'interrupted'} {self.progress_label}", markup=False)

    # Scoped to this synchronous CLI run; restored on exceptions and Ctrl+C.
    with bar, patch.object(benchmark, "TraceLogger", ProgressTrace):
        token = _ACTIVITY.set(activity)
        error_token = _TASK_ERROR.set(task_error)
        try:
            yield
        finally:
            _ACTIVITY.reset(token)
            _TASK_ERROR.reset(error_token)
