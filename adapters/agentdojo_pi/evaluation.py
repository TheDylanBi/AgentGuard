"""Optional task isolation using official AgentDojo task runners and checkers."""
import warnings
from policy.intent_output import IntentStageError
from .errors import ActionModelError
from .progress import report_task_error


class ConsecutiveTaskErrors(RuntimeError):
    pass


def benchmark_with_task_errors(pipeline, suite, *, attack=None, user_tasks=None, injection_tasks=None,
                               logdir=None, force_rerun=True, benchmark_version=None,
                               on_update=lambda state: None, max_consecutive_errors=3):
    from agentdojo.benchmark import run_task_without_injection_tasks, run_task_with_injection_tasks
    if max_consecutive_errors < 1:
        raise ValueError("max_consecutive_errors must be positive")
    users = [suite.get_user_task_by_id(t) for t in user_tasks] if user_tasks is not None else list(suite.user_tasks.values())
    injections = ([suite.get_injection_task_by_id(t) for t in dict.fromkeys(injection_tasks)]
                  if injection_tasks is not None else list(suite.injection_tasks.values()))
    plan = []
    if attack is None:
        plan = [("clean", task, None) for task in users]
    else:
        if attack.is_dos_attack:
            injections = [next(iter(suite.injection_tasks.values()))]
        else:
            plan += [("prescreen", task, None) for task in injections]
        plan += [("attack", task, injection) for task in users for injection in injections]
    result = {"utility_results": {}, "security_results": {}, "injection_tasks_utility_results": {}}
    state = {"result": result, "task_outcomes": [], "task_errors": [],
             "planned": {phase: sum(p == phase for p, _, _ in plan) for phase in ("clean", "prescreen", "attack")}}
    on_update(state)
    consecutive = 0
    for phase, task, injection in plan:
        row = {"phase": phase, "user_task": task.ID if phase != "prescreen" else None,
               "injection_task": task.ID if phase == "prescreen" else injection.ID if injection else None}
        try:
            if phase in ("clean", "prescreen"):
                utility, security = run_task_without_injection_tasks(
                    suite, pipeline, task, logdir, force_rerun, benchmark_version)
                if phase == "prescreen":
                    result["injection_tasks_utility_results"][task.ID] = utility
                else:
                    result["utility_results"][(task.ID, "")] = utility
                    result["security_results"][(task.ID, "")] = security
            else:
                utility_rows, security_rows = run_task_with_injection_tasks(suite, pipeline, task, attack,
                    logdir, force_rerun, [injection.ID], benchmark_version)
                result["utility_results"].update(utility_rows)
                result["security_results"].update(security_rows)
                utility, security = utility_rows[(task.ID, injection.ID)], security_rows[(task.ID, injection.ID)]
            state["task_outcomes"].append({**row, "status": "scored", "utility": utility, "security": security})
            consecutive = 0
        except (IntentStageError, ActionModelError) as error:
            # A missing policy is not a defense success. No fabricated official
            # score, no fallback policy, no replay of a partially executed task.
            key = "intent_diagnostic" if isinstance(error, IntentStageError) else "action_diagnostic"
            local = error.task_local
            failure = {**row, "error_type": type(error).__name__, key: error.diagnostic,
                       "error_scope": "task" if local else "service_or_unknown"}
            state["task_errors"].append(failure)
            state["task_outcomes"].append({**row, "status": "error", "utility": None, "security": None})
            # Exhausting one task's context/output is not evidence that the
            # server is unavailable. Keep its null scores and try other tasks.
            consecutive = 0 if local else consecutive + 1
            report_task_error(phase, task.ID + ("/" + injection.ID if injection else ""))
        except BaseException as error:
            # A bridge invariant, interruption or unexpected programming failure
            # still aborts. Preserve the identity without fabricating a score.
            state["interrupted_task"] = {**row, "status": "interrupted", "error_type": type(error).__name__}
            on_update(state)
            raise
        if consecutive >= max_consecutive_errors:
            state["halt_reason"] = {"code": "consecutive_service_or_unknown_errors", "count": consecutive,
                                    "task": row}
        on_update(state)  # Persist after every scored/error task, including the last error before abort.
        if consecutive >= max_consecutive_errors:
            raise ConsecutiveTaskErrors(f"Stopped after {consecutive} consecutive service/unknown model errors; see summary.json")
    if attack is not None and not attack.is_dos_attack and (
            len(result["injection_tasks_utility_results"]) != len(injections)
            or not all(result["injection_tasks_utility_results"].values())):
        warnings.warn("Some injection-goal prescreens failed or errored; see task_outcomes in summary.json.")
    return result
