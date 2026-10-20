"""Run the official AgentDojo evaluator with a pi SDK pipeline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime
from .host import load_manifest, make_contract, PROJECT


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def record_results(metadata, result, runs, *, has_attack, state=None, final=True):
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
    parser.add_argument("--intent-format", choices=("rules", "boundary"), default="rules",
                        help="Initial policy representation; boundary retains unresolved parameters explicitly")
    parser.add_argument("--suite", default="workspace")
    parser.add_argument("--benchmark-version", default="v1.2.2")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("workspace_manifest.json"))
    parser.add_argument("--pi-package", type=Path, default=Path("D:/Pi/pi-node/current/node_modules/@earendil-works/pi-coding-agent"))
    parser.add_argument("--pi-agent-dir", type=Path, default=Path.home() / ".pi/agent")
    parser.add_argument("--node", default="D:/Pi/pi-node/current/node.exe")
    parser.add_argument("--provider")
    parser.add_argument("--model")
    parser.add_argument("--user-task", action="append")
    parser.add_argument("--injection-task", action="append")
    parser.add_argument("--attack")
    parser.add_argument("--business-policy", type=Path)
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
    # Only the public simulation clock from a CLEAN environment. Do not inspect
    # injected environments, task answers, calendar events or resource contents.
    trusted_day = None
    if args.suite == "workspace":
        trusted_day = suite.load_and_inject_default_environment({}).calendar.current_day.isoformat()
    pipeline = PiPipeline(manifest=snapshot, pi_package=args.pi_package,
        pi_agent_dir=args.pi_agent_dir, provider=args.provider, model=args.model,
        mode=args.mode, output=output / "audit", node=args.node,
        action_output_budget=args.action_output_budget,
        read_preflight=args.read_preflight,
        intent_format=args.intent_format,
        business_policy=business, max_turns=args.max_turns, timeout=args.timeout,
        trusted_current_day=trusted_day)
    import agentdojo
    source = Path(agentdojo.__file__).resolve().parents[2]
    revision = subprocess.run(["git", "-c", f"safe.directory={source.as_posix()}", "-C", str(source),
                               "rev-parse", "HEAD"], capture_output=True, text=True)
    metadata = {"status": "running", "evaluation_scope": "simulation_policy_layer",
        "mode": args.mode, "suite": args.suite, "benchmark_version": args.benchmark_version,
        "agentdojo_revision": revision.stdout.strip() if revision.returncode == 0 else None,
        "pi_version": package["version"], "provider": args.provider, "model": args.model,
        "continue_on_error": args.continue_on_error, "max_consecutive_errors": args.max_consecutive_errors,
        "intent_model": os.environ.get("ICB_INTENT_LLM_MODEL") if args.mode == "guarded" else None,
        "intent_output_format": os.environ.get("ICB_INTENT_LLM_OUTPUT_FORMAT", "text"),
        "intent_compact_json": os.environ.get("ICB_INTENT_LLM_COMPACT_JSON", "false") == "true",
        "attack": args.attack, "user_tasks": args.user_task, "injection_tasks": args.injection_task,
        "max_turns": args.max_turns, "timeout": args.timeout, "trusted_current_day": trusted_day,
        "action_output_budget": args.action_output_budget,
        "read_preflight": bool(args.read_preflight and args.mode == "guarded"),
        "intent_format": args.intent_format,
        "pi_model_config_sha256": digest(args.pi_agent_dir / "models.json")
            if (args.pi_agent_dir / "models.json").is_file() else None,
        "manifest_sha256": digest(snapshot), "business_policy_sha256": digest(business) if business else None,
        "source_sha256": {str(p.relative_to(PROJECT)): digest(p)
            for folder in ("policy", "adapters/agentdojo_pi")
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
