"""Compare matched baseline/guarded summaries without scoring missing tasks."""
import argparse
import json
from pathlib import Path


MATCH_FIELDS = ("suite", "benchmark_version", "agentdojo_revision", "pi_version", "provider", "model",
                "attack", "max_turns", "timeout", "trusted_current_day", "action_output_budget",
                "manifest_sha256", "business_policy_sha256", "source_sha256", "pi_model_config_sha256")


def compare_summaries(baseline, guarded):
    if baseline.get("mode") != "baseline" or guarded.get("mode") != "guarded":
        raise ValueError("Expected baseline and guarded summaries in that order")
    missing = [key for key in MATCH_FIELDS if key not in baseline or key not in guarded]
    mismatches = [key for key in MATCH_FIELDS if baseline.get(key) != guarded.get(key)]
    if missing or mismatches:
        raise ValueError("Unmatched evaluation configuration: " + ", ".join(sorted(set(missing + mismatches))))
    for key in ("user_tasks", "injection_tasks"):
        if set(baseline.get(key) or []) != set(guarded.get(key) or []):
            raise ValueError("Unmatched task selections: " + key)

    def indexed(summary, metric):
        result = {}
        for row in summary["official_results"][metric]:
            key = row["user_task"], row["injection_task"]
            if key in result or type(row["value"]) is not bool:
                raise ValueError("Duplicate or non-boolean official score")
            result[key] = row["value"]
        return result

    b, g = (indexed(s, "utility_results") for s in (baseline, guarded))
    bs, gs = (indexed(s, "security_results") for s in (baseline, guarded))
    keys = set(b) | set(g)
    if baseline.get("user_tasks") and (not baseline["attack"] or baseline.get("injection_tasks")):
        keys |= {(user, injection) for user in baseline["user_tasks"]
                 for injection in (baseline["injection_tasks"] if baseline["attack"] else [""])}
    # Include failed/unprocessed tasks even when neither side has a score.
    for summary in (baseline, guarded):
        for row in summary.get("task_outcomes", []):
            if row["phase"] != "prescreen":
                keys.add((row["user_task"], row.get("injection_task") or ""))
    rows = []
    counts = {key: 0 for key in ("both_succeeded", "baseline_only_succeeded", "guarded_only_succeeded",
                                "both_failed", "unscored_on_either_side")}
    for key in sorted(keys):
        left, right = b.get(key), g.get(key)
        category = ("unscored_on_either_side" if left is None or right is None else
                    "both_succeeded" if left and right else "baseline_only_succeeded" if left else
                    "guarded_only_succeeded" if right else "both_failed")
        counts[category] += 1
        rows.append({"user_task": key[0], "injection_task": key[1], "baseline_utility": left,
                     "guarded_utility": right, "category": category,
                     "baseline_attack_success": bs.get(key) if baseline["attack"] else None,
                     "guarded_attack_success": gs.get(key) if guarded["attack"] else None})
    paired = [row for row in rows if row["category"] != "unscored_on_either_side"]
    return {"matched_configuration": True, "counts": counts, "paired_scored": len(paired),
            "baseline_utility_on_paired": sum(r["baseline_utility"] for r in paired) / len(paired) if paired else None,
            "guarded_utility_on_paired": sum(r["guarded_utility"] for r in paired) / len(paired) if paired else None,
            "baseline_status": baseline["status"], "guarded_status": guarded["status"],
            "task_accounting": {"baseline": baseline.get("task_accounting"),
                                "guarded": guarded.get("task_accounting")},
            "controlled_stops": {"baseline": baseline.get("controlled_stops", 0),
                                 "guarded": guarded.get("controlled_stops", 0)},
            "note": "Paired observations only, not causal proof. Unscored rows are not failures or defense successes. "
                    "Stopped runs and failed attack-goal prescreens limit security interpretation. "
                    "Same configuration does not establish identical stochastic model outputs or server weights.",
            "rows": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--guarded", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = compare_summaries(json.loads(args.baseline.read_text(encoding="utf-8")),
                               json.loads(args.guarded.read_text(encoding="utf-8")))
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
