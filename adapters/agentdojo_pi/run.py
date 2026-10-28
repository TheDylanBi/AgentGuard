"""Run the official AgentDojo evaluator with a pi SDK pipeline."""
import argparse
import locale
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime
from .host import load_manifest, make_contract, PROJECT
from attestation.hashing import object_hash


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def record_results(metadata, result, runs, *, has_attack, state=None, final=True):
    from policy.review_metrics import review_metrics
    metadata['authorization_diagnostics']=review_metrics(runs)
    metadata["official_results"] = {
        key: [{"user_task": pair[0], "injection_task": pair[1], "value": value}
              for pair, value in result[key].items()]
        for key in ("utility_results", "security_results")}
    metadata["injection_tasks_utility_results"] = result["injection_tasks_utility_results"]
    metadata["metrics"] = {}
    for key in ("utility_results", "security_results"):
        values = list(result[key].values())
        metadata["metrics"][key] = {"true": sum(values), "count": len(values),
                                    "rate": sum(values) / len(values) if values else None}
    # AgentDojo's security boolean means the ATTACK GOAL succeeded.
    # Without an attack its placeholder True is not an attack measurement.
    metadata["metrics"]["attack_success_rate"] = (
        metadata["metrics"]["security_results"]["rate"] if has_attack else None)
    stopped = sum(run["status"] in ("stopped", "answered_after_stop") for run in runs)
    metadata["controlled_stops"] = stopped
    metadata["answers_after_stop"] = sum(run["status"] == "answered_after_stop" for run in runs)
    if stopped:
        metadata["metrics"]["attack_success_rate"] = None
        metadata["metrics"]["interpretation"] = (
            "Raw official results include controlled stops (possibly during injection-goal prescreening). "
            "Do not interpret an unmet attacker goal in a stopped run as proven successful defense.")
    metadata["status"] = "completed_with_stops" if stopped else "completed"
    if state is not None:
        from collections import Counter
        metadata['task_error_categories']=dict(Counter(
            row.get('error_category','legacy_or_unclassified') for row in state['task_errors']))
        metadata["task_errors"] = state["task_errors"]
        metadata["task_outcomes"] = state["task_outcomes"]
        if state.get("interrupted_task"):
            metadata["interrupted_task"] = state["interrupted_task"]
        if state.get("halt_reason"):
            metadata["halt_reason"] = state["halt_reason"]
        planned = sum(state["planned"].values())
        processed = len(state["task_outcomes"])
        errors = len(state["task_errors"])
        metadata["task_accounting"] = {"planned_by_phase": state["planned"], "planned": planned,
            "processed": processed, "scored": processed - errors, "errors": errors,
            "remaining": planned - processed}
        for value in metadata["metrics"].values():
            if isinstance(value, dict) and "rate" in value:
                value["scored_rate"] = value["rate"]
                if errors or not final:
                    value["rate"] = None
        if errors or not final:
            metadata["metrics"]["attack_success_rate"] = None
            metadata["metrics"]["interpretation"] = (
                "Errors/unprocessed tasks have no official score. scored_rate describes scored rows only, "
                "not the full benchmark. Inspect task_outcomes and task_accounting.")
        if errors:
            metadata["status"] = "completed_with_errors"
    if not final:
        metadata["status"] = "running"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("baseline", "guarded"), required=True)
    parser.add_argument("--intent-format", choices=("rules", "boundary", "review"), default="rules",
                        help="rules/boundary: initial policy; review: experimental per-call semantic authorization")
    parser.add_argument("--suite", default="workspace")
    parser.add_argument('--review-coordination',choices=('legacy','scoped'),default='scoped',
                        help='Review only: legacy task-level stops, or scoped recovery plus one execution checkpoint')
    from policy.task_derivations import validate_reminder_window
    parser.add_argument('--calendar-reminder-window',type=validate_reminder_window,
                        help='Explicit shared baseline/guarded preference HH:MM-HH:MM for date-only reminders; off by default')
    from policy.execution_preferences import iso_day,local_time
    parser.add_argument('--trusted-current-day',type=iso_day,help='Explicit simulation date override shared by both modes')
    parser.add_argument('--trusted-current-time',type=local_time,help='Explicit simulation current time HH:MM; never inferred from task answers')
    parser.add_argument('--payment-date-policy',choices=('explicit','run-day'),default='explicit',
                        help='Immediate transfers without a user date: require a date, or use the recorded trusted run day')
    parser.add_argument('--equal-share-policy',choices=('explicit','two-party'),default='explicit',
                        help='Optional shared convention for a meal shared by the user and one friend')
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--manifest", type=Path,
                        help="Defaults to the reviewed manifest belonging to the selected suite")
    parser.add_argument("--pi-package", type=Path, default=Path("D:/Pi/pi-node/current/node_modules/@earendil-works/pi-coding-agent"))
    parser.add_argument("--pi-agent-dir", type=Path, default=Path.home() / ".pi/agent")
    parser.add_argument("--node", default="D:/Pi/pi-node/current/node.exe")
    parser.add_argument("--provider")
    parser.add_argument("--model")
    parser.add_argument("--user-task", action="append")
    parser.add_argument("--injection-task", action="append")
    parser.add_argument("--attack")
    parser.add_argument("--business-policy", type=Path)
    parser.add_argument('--authorization-contracts',type=Path,
                        help='Explicit trusted approval scopes, bound to the original request; never model output')
    parser.add_argument("--max-turns", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--action-output-budget", choices=("sdk", "model"), default="sdk",
                        help="sdk: keep pi context estimate; model: send configured maxTokens (OpenAI-compatible only)")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--read-preflight", action="store_true",
                        help="Generate scoped prerequisite read rules from the original task before main rules")
    parser.add_argument("--continue-on-error", action="store_true",
                        help="Record intent/action model errors separately and continue other tasks")
    parser.add_argument("--max-consecutive-errors", type=int, default=3,
                        help="Stop after consecutive service/unknown errors; task-local output errors remain unscored")
    parser.add_argument("--no-progress", action="store_true", help="Disable task progress display")
    parser.add_argument("--check", action="store_true", help="Validate installation and manifest without model calls")
    parser.add_argument("--describe-contracts", action="store_true", help="Include parameter contracts in --check output")
    args = parser.parse_args(argv)
    dataset_encoding = locale.getpreferredencoding(False)
    if dataset_encoding.lower().replace('-', '') not in {'utf8', 'utf8sig'}:
        import warnings
        warnings.warn('AgentDojo dataset reads use '+dataset_encoding+
                      '; run Python with -X utf8 to avoid corrupting UTF-8 resource identities.', stacklevel=2)
    if args.authorization_contracts and (args.mode!='guarded' or args.intent_format!='review'):
        parser.error('authorization-contracts requires guarded review mode')
    from policy.scoped_authorization import load_contracts
    trusted_contracts=load_contracts(args.authorization_contracts)
    if args.intent_format == "review" and (args.mode != "guarded" or args.read_preflight):
        parser.error("--intent-format review requires --mode guarded and no --read-preflight")
    if args.intent_format=='review':
        from policy.call_review import CallReviewer
        CallReviewer('Configuration check only; no model calls.')
    if args.describe_contracts and not args.check:
        parser.error("describe-contracts requires check")
    if args.max_consecutive_errors < 1:
        parser.error("max-consecutive-errors must be positive")
    if args.max_turns < 1 or args.timeout <= 0:
        parser.error("max-turns and timeout must be positive")
    if args.injection_task and not args.attack:
        parser.error("injection-task requires attack")
    if args.business_policy and args.mode == "baseline":
        parser.error("business-policy is only applied in guarded mode")
    suite = get_suite(args.benchmark_version, args.suite)
    if args.manifest is None:
        args.manifest = Path(__file__).with_name(args.suite + '_manifest.json')
    runtime = FunctionsRuntime(suite.tools)
    manifest = load_manifest(args.manifest, runtime)
    contracts = {name: make_contract(name, function.parameters, manifest["tools"][name]).report()
                 for name, function in runtime.functions.items()}
    if manifest["suite"] != args.suite:
        parser.error("Manifest belongs to another suite")
    for selection in (args.user_task, args.injection_task):
        if selection and len(selection) != len(set(selection)):
            parser.error("Task selections must not contain duplicate IDs")
    for task in args.user_task or []:
        suite.get_user_task_by_id(task)
    for task in args.injection_task or []:
        suite.get_injection_task_by_id(task)
    from policy.business_rules import BusinessPolicy
    BusinessPolicy(args.business_policy)
    package = json.loads((args.pi_package / "package.json").read_text(encoding="utf-8"))
    subprocess.run([args.node, "--check", str(Path(__file__).with_name("pi_runner.mjs"))], check=True)
    if args.attack:
        from agentdojo.attacks.attack_registry import ATTACKS
        if args.attack not in ATTACKS:
            parser.error("Unknown attack: " + args.attack)
    if args.check:
        print(json.dumps({"status": "configuration_valid", "suite": args.suite,
                          "tools": len(runtime.functions), "pi_version": package["version"],
                          "benchmark_version": args.benchmark_version,
                          "parameter_count": sum(len(c["parameters"]) for c in contracts.values()),
                          **({"parameter_contracts": contracts} if args.describe_contracts else {}),
                          "note": "No model calls; provider connectivity is not tested"}, indent=2))
        return 0
    if not args.provider or not args.model:
        parser.error("provider and model are required for evaluation")
    from .pipeline import PiPipeline
    from policy.intent_anchor import intent_llm_configured
    if args.mode == "guarded" and not intent_llm_configured():
        parser.error("Configure independent ICB_INTENT_LLM_BASE_URL/API_KEY/MODEL")
    output = (args.output or PROJECT / "results" / f"agentdojo_pi_{args.mode}_{time.time_ns()}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    # Freeze operator configuration for every task in this run.
    snapshot = output / "manifest.json"
    snapshot.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (output / "parameter-contracts.json").write_text(json.dumps(contracts, indent=2), encoding="utf-8")
    business = None
    if args.business_policy:
        business = output / "business-policy.json"
        business.write_bytes(args.business_policy.read_bytes())
    approval_snapshot=None
    if args.authorization_contracts:
        approval_snapshot=output/'authorization-contracts.json'
        approval_snapshot.write_text(json.dumps({'version':1,'contracts':trusted_contracts},indent=2),encoding='utf-8')
    # Only the public simulation clock from a CLEAN environment. Do not inspect
    # injected environments, task answers, calendar events or resource contents.
    calendar=getattr(suite.load_and_inject_default_environment({}),'calendar',None)
    trusted_day=args.trusted_current_day or (calendar.current_day.isoformat() if calendar is not None else None)
    payment_day=trusted_day
    if payment_day is None and args.payment_date_policy=='run-day':
        from datetime import date
        payment_day=date.today().isoformat()
    pipeline = PiPipeline(manifest=snapshot, pi_package=args.pi_package,
        pi_agent_dir=args.pi_agent_dir, provider=args.provider, model=args.model,
        mode=args.mode, output=output / "audit", node=args.node,
        action_output_budget=args.action_output_budget,
        read_preflight=args.read_preflight,
        intent_format=args.intent_format,
        review_coordination=args.review_coordination,
        calendar_reminder_window=args.calendar_reminder_window,
        trusted_current_time=args.trusted_current_time,payment_date_policy=args.payment_date_policy,
        payment_execution_day=payment_day,
        equal_share_policy=args.equal_share_policy,
        authorization_contracts=trusted_contracts,
        business_policy=business, max_turns=args.max_turns, timeout=args.timeout,
        trusted_current_day=trusted_day)
    import agentdojo
    source = Path(agentdojo.__file__).resolve().parents[2]
    revision = subprocess.run(["git", "-c", f"safe.directory={source.as_posix()}", "-C", str(source),
                               "rev-parse", "HEAD"], capture_output=True, text=True)
    metadata = {"status": "running", "evaluation_scope": "simulation_policy_layer",
        "dataset_text_encoding":dataset_encoding,
        "mode": args.mode, "suite": args.suite, "benchmark_version": args.benchmark_version,
        "agentdojo_revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "pi_version": package["version"], "provider": args.provider, "model": args.model,
        "continue_on_error": args.continue_on_error, "max_consecutive_errors": args.max_consecutive_errors,
        "intent_model": os.environ.get("ICB_INTENT_LLM_MODEL") if args.mode == "guarded" else None,
        "intent_output_format": os.environ.get("ICB_INTENT_LLM_OUTPUT_FORMAT", "text"),
        "intent_compact_json": os.environ.get("ICB_INTENT_LLM_COMPACT_JSON", "false") == "true",
        "attack": args.attack, "user_tasks": args.user_task, "injection_tasks": args.injection_task,
        "max_turns": args.max_turns, "timeout": args.timeout, "trusted_current_day": trusted_day,
        'calendar_reminder_window':args.calendar_reminder_window,
        'trusted_current_time':args.trusted_current_time,'payment_date_policy':args.payment_date_policy,
        'payment_execution_day':payment_day,
        'equal_share_policy':args.equal_share_policy,
        "action_output_budget": args.action_output_budget,
        "read_preflight": bool(args.read_preflight and args.mode == "guarded"),
        "intent_format": args.intent_format,
        'coordination_profile':('scoped_recovery_and_single_checkpoint_v1' if args.review_coordination=='scoped' else 'legacy')
            if args.mode=='guarded' and args.intent_format=='review' else 'off',
        "intent_config_sha256": object_hash({key: os.environ.get(key) for key in (
            "ICB_INTENT_LLM_BASE_URL", "ICB_INTENT_LLM_MODEL", "ICB_INTENT_LLM_TIMEOUT_SECONDS",
            "ICB_INTENT_LLM_MAX_TOKENS", "ICB_INTENT_LLM_OUTPUT_FORMAT",
            "ICB_INTENT_LLM_COMPACT_JSON", "ICB_INTENT_LLM_ENABLE_THINKING",
            "ICB_REVIEW_OUTPUT_FORMAT", "ICB_REVIEW_MAX_TOKENS", "ICB_REVIEW_ENABLE_THINKING",
            "ICB_REVIEW_REASONING_EFFORT", "ICB_REVIEW_RETRY_OUTPUT_FORMAT",
            "ICB_REVIEW_RETRY_MAX_TOKENS", "ICB_REVIEW_RETRY_ENABLE_THINKING",
            "ICB_REVIEW_RETRY_REASONING_EFFORT", "ICB_REVIEW_THINKING_MODE",
            "ICB_REVIEW_RETRY_THINKING_MODE", "ICB_REVIEW_CALL_TIMEOUT_SECONDS",
            "ICB_REVIEW_ACTION_RESERVE_SECONDS", "ICB_REVIEW_MIN_ATTEMPT_SECONDS")}),
        "pi_model_config_sha256": digest(args.pi_agent_dir / "models.json")
            if (args.pi_agent_dir / "models.json").is_file() else None,
        "manifest_sha256": digest(snapshot), "business_policy_sha256": digest(business) if business else None,
        'authorization_contracts_sha256':digest(approval_snapshot) if approval_snapshot else None,
        "source_sha256": {str(p.relative_to(PROJECT)): digest(p)
            for folder in ("policy", "adapters/agentdojo_pi", "gateway", "attestation")
            for p in (PROJECT / folder).rglob("*") if p.is_file() and p.suffix in (".py", ".mjs", ".yaml")}}
    def save():
        metadata["runs"] = pipeline.runs
        metadata["intent_diagnostic"] = pipeline.last_intent_diagnostic
        temporary = output / "summary.json.tmp"
        temporary.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        temporary.replace(output / "summary.json")
    save()
    partial_state = None
    def checkpoint(state):
        nonlocal partial_state
        partial_state = state
        record_results(metadata, state["result"], pipeline.runs, has_attack=bool(args.attack), state=state, final=False)
        save()
    try:
        from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
        from agentdojo.logging import OutputLogger
        common = dict(logdir=output / "official", force_rerun=True, user_tasks=args.user_task,
                      benchmark_version=args.benchmark_version)
        from .progress import task_progress
        attack = None
        if args.attack:
            from agentdojo.attacks import load_attack
            attack = load_attack(args.attack, suite, pipeline)
        with OutputLogger(str(output / "official")), task_progress(
                suite, args.user_task, args.injection_task, attack, enabled=not args.no_progress):
            if args.continue_on_error:
                from .evaluation import benchmark_with_task_errors
                result = benchmark_with_task_errors(pipeline, suite, attack=attack,
                    injection_tasks=args.injection_task, on_update=checkpoint,
                    max_consecutive_errors=args.max_consecutive_errors, **common)
            elif args.attack:
                result = benchmark_suite_with_injections(pipeline, suite, attack,
                                                         injection_tasks=args.injection_task, **common)
            else:
                result = benchmark_suite_without_injections(pipeline, suite, **common)
        record_results(metadata, result, pipeline.runs, has_attack=bool(args.attack), state=partial_state)

    except BaseException as error:
        metadata["status"] = "incomplete"
        metadata["error_type"] = type(error).__name__
        raise
    finally:
        save()
        print("Results: " + str(output / "summary.json"))
    if metadata.get("task_errors"):
        print(f"Evaluation finished with {len(metadata['task_errors'])} model-stage errors; "
              "these tasks have no official score. See task_errors in summary.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
