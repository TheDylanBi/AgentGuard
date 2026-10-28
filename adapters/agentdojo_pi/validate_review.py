"""Pre-registered, sequential real-model comparison; never changes policy.

Uses credentials already supplied by the caller's environment and pi agent
directory. Child output stays in the result directory; no secrets are printed.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from .host import PROJECT
from .review_report import compare_formats, summarize


def source_fingerprint():
    return {str(p.relative_to(PROJECT)): hashlib.sha256(p.read_bytes()).hexdigest()
        for directory in ("policy", "adapters/agentdojo_pi")
        for p in (PROJECT / directory).rglob("*") if p.is_file() and p.suffix in (".py", ".mjs", ".yaml", ".json")}


def protocol(include_full_attack=False, clean_only=False):
    # Counterbalance clean trial order. Pilot IDs are fixed before any results.
    trials = [{"id": f"clean_{index + 1}_{fmt}", "intent_format": fmt, "phase": "clean"}
              for index, formats in enumerate((("rules", "review"), ("review", "rules"))) for fmt in formats]
    if clean_only:
        if include_full_attack:
            raise ValueError("Clean-only validation cannot include attacks")
        return trials
    trials += [{"id": "pilot_" + fmt, "intent_format": fmt, "phase": "pilot",
                "users": [f"user_task_{i}" for i in range(4)],
                "injections": [f"injection_task_{i}" for i in range(4)]} for fmt in ("rules", "review")]
    if include_full_attack:
        trials.append({"id": "full_review", "intent_format": "review", "phase": "full"})
    return trials


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def denial_rules(folder):
    result = Counter()
    for path in (folder / "audit").glob("audit-*.jsonl"):
        for line in path.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if row.get("event") == "simulation_denied":
                result[row["rule"]] += 1
    return dict(result)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pi-agent-dir", required=True, type=Path)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--node", default="D:/Pi/pi-node/current/node.exe")
    parser.add_argument("--pi-package", type=Path, default=Path("D:/Pi/pi-node/current/node_modules/@earendil-works/pi-coding-agent"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--include-full-attack", action="store_true")
    parser.add_argument("--clean-only", action="store_true", help="Only the two rounds of 40 clean tasks per mode")
    args = parser.parse_args(argv)
    if args.clean_only and args.include_full_attack:
        parser.error("--clean-only cannot be combined with --include-full-attack")
    output = (args.output or PROJECT / "results" / f"agentdojo_pi_review_validation_{time.time_ns()}").resolve()
    output.mkdir(parents=True, exist_ok=False)
    fingerprint = source_fingerprint()
    model_file = args.pi_agent_dir.resolve() / "models.json"
    config_digest = hashlib.sha256(model_file.read_bytes()).hexdigest()
    plan = {"status": "running", "created_unix": time.time(), "suite": "workspace",
            "benchmark_version": "v1.2.2", "source_sha256": fingerprint,
            "pi_model_config_sha256": config_digest,
            "max_turns": 16, "timeout": 300, "attack": "tool_knowledge",
            "trials": protocol(args.include_full_attack, args.clean_only),
            "limits": "Server weights and stochasticity are not controlled. Full attack is review-only; "
                      "ASR comparisons use the fixed pilot, not historical runs. No automatic policy changes."}
    write_json(output / "protocol.json", plan)
    results = {}
    base = [sys.executable, "-B", "-m", "adapters.agentdojo_pi.run", "--mode", "guarded",
        "--suite", "workspace", "--benchmark-version", "v1.2.2",
        "--pi-agent-dir", str(args.pi_agent_dir.resolve()), "--provider", args.provider, "--model", args.model,
        "--pi-package", str(args.pi_package.resolve()), "--node", args.node,
        "--max-turns", "16", "--timeout", "300", "--action-output-budget", "model",
        "--continue-on-error", "--no-progress"]
    started = time.monotonic()
    try:
        for trial in plan["trials"]:
            if source_fingerprint() != fingerprint or hashlib.sha256(model_file.read_bytes()).hexdigest() != config_digest:
                raise RuntimeError("Source/config changed during the experiment; refusing mixed-version results")
            folder = output / trial["id"]
            command = base + ["--intent-format", trial["intent_format"], "--output", str(folder)]
            if trial["phase"] != "clean":
                command += ["--attack", "tool_knowledge"]
            for task in trial.get("users", []):
                command += ["--user-task", task]
            for task in trial.get("injections", []):
                command += ["--injection-task", task]
            plan["active_trial"] = trial["id"]
            write_json(output / "protocol.json", plan)
            print("Starting " + trial["id"] + ": " + str(folder / "summary.json"), flush=True)
            env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}
            with (output / (trial["id"] + ".log")).open("w", encoding="utf-8") as log:
                process = subprocess.run(command, cwd=PROJECT, env=env, stdout=log, stderr=subprocess.STDOUT)
            trial["exit_code"] = process.returncode
            if (folder / "summary.json").exists():
                data = json.loads((folder / "summary.json").read_text(encoding="utf-8"))
                results[trial["id"]] = {**summarize(data), "summary": str(folder / "summary.json"),
                                         "denial_rules": denial_rules(folder)}
                write_json(output / "report.json", results)
            write_json(output / "protocol.json", plan)
            if process.returncode or trial["id"] not in results or not data["status"].startswith("completed"):
                raise RuntimeError("Operational failure in " + trial["id"] + "; preserve partial results, stop the batch")
            # Matching every completed pair detects service/model config drift.
            pairs = [("clean_1_rules", "clean_1_review"), ("clean_2_rules", "clean_2_review"),
                     ("pilot_rules", "pilot_review")]
            for left, right in pairs:
                if left in results and right in results:
                    a = json.loads(Path(results[left]["summary"]).read_text(encoding="utf-8"))
                    b = json.loads(Path(results[right]["summary"]).read_text(encoding="utf-8"))
                    write_json(output / (left + "_vs_" + right + ".json"), compare_formats(a, b))
            print("Finished " + trial["id"] + ": " + data["status"], flush=True)
        plan["status"] = "completed"
    except BaseException as error:
        plan.update(status="incomplete", error_type=type(error).__name__)
        raise
    finally:
        plan["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_json(output / "protocol.json", plan)
        print("Validation results: " + str(output), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
