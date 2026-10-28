"""Report complete intent-format trials, including missing/error observations."""
import argparse
from collections import Counter
import copy
import json
from pathlib import Path

from .compare import compare_summaries
from policy.review_metrics import review_metrics


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lo = int(position)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (position - lo)


def summarize(summary):
    phases = {}
    planned = summary.get("task_accounting", {}).get("planned_by_phase", {})
    outcomes = summary.get("task_outcomes", [])
    for phase in ("clean", "prescreen", "attack"):
        rows = [row for row in outcomes if row["phase"] == phase]
        total = planned.get(phase)
        if total is None or not total:
            continue
        scored = [r for r in rows if r["status"] == "scored"]
        success = sum(r["utility"] is True for r in scored)
        durations = [r["elapsed_seconds"] for r in rows if "elapsed_seconds" in r]
        attacks = sum(r["security"] is True for r in scored) if phase == "attack" else None
        phases[phase] = {"planned": total, "processed": len(rows), "scored": len(scored),
            "successful": success, "scored_unsuccessful": len(scored) - success,
            "errors": sum(r["status"] == "error" for r in rows), "unprocessed": total - len(rows),
            "observed_success_over_planned": success / total,
            "utility_on_scored": success / len(scored) if scored else None,
            "score_coverage": len(scored) / total,
            "observed_attack_successes": attacks,
            "attack_success_on_scored": attacks / len(scored) if scored and phase == "attack" else None,
            "latency": {"measured_tasks": len(durations), "sum_seconds": sum(durations),
                        "p50_seconds": percentile(durations, .5), "p95_seconds": percentile(durations, .95)}}
    reviews = [review for run in summary.get("runs", []) for review in run.get("reviews", [])]
    return {"status": summary["status"], "intent_format": summary.get("intent_format"),
        "phases": phases, "controlled_stops": summary.get("controlled_stops", 0),
        "review_requests": sum(r.get("request_count", 0) for r in reviews),
        "review_seconds": sum(r.get("elapsed_seconds", 0) for r in reviews),
        "review_decisions": dict(Counter(r["result"]["decision"] for r in reviews if r.get("result"))),
        "review_errors": sum(r["status"] in ("error", "invalidated") for r in reviews),
        "authorization_diagnostics": review_metrics(summary.get("runs", [])),
        "initial_intent_seconds": sum(r.get("initial_intent_seconds", 0) for r in summary.get("runs", [])),
        "note": "Observed success/plan is not an official error-as-failure score. Scored ASR includes stops; "
                "check prescreens and stops before attributing any defense. Missing timing is not zero latency."}


def compare_formats(left, right):
    if (left.get("mode") != "guarded" or right.get("mode") != "guarded"
            or left.get("intent_format") == right.get("intent_format")):
        raise ValueError("Expected two different guarded intent formats")
    extra = ("intent_model", "intent_output_format", "intent_compact_json", "read_preflight", "intent_config_sha256")
    for key in extra:
        if key not in left or key not in right or left[key] != right[key]:
            raise ValueError("Unmatched intent configuration: " + key)
    # Reuse strict source/config/task matching; do not mutate the input records.
    a, b = copy.deepcopy(left), copy.deepcopy(right)
    a["mode"] = "baseline"
    paired = compare_summaries(a, b)
    return {"left": summarize(left), "right": summarize(right),
        "paired_scored": paired["paired_scored"],
        "counts": {"both_succeeded": paired["counts"]["both_succeeded"],
                   "left_only_succeeded": paired["counts"]["baseline_only_succeeded"],
                   "right_only_succeeded": paired["counts"]["guarded_only_succeeded"],
                   "both_failed": paired["counts"]["both_failed"],
                   "unscored_on_either_side": paired["counts"]["unscored_on_either_side"]},
        "rows": [{"user_task": r["user_task"], "injection_task": r["injection_task"],
                  "left_utility": r["baseline_utility"], "right_utility": r["guarded_utility"],
                  "left_attack_success": r["baseline_attack_success"],
                  "right_attack_success": r["guarded_attack_success"]} for r in paired["rows"]],
        "note": paired["note"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", required=True, type=Path)
    parser.add_argument("--right", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    left = json.loads(args.left.read_text(encoding="utf-8"))
    result = compare_formats(left, json.loads(args.right.read_text(encoding="utf-8"))) if args.right else summarize(left)
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
