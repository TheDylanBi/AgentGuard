"""R-Judge safety judgment, policy-assisted judgment, and legacy replay.

Default --protocol official reproduces full-record two-stage safety judgment.
--protocol policy-assisted adds this framework's causal policy observations.
--protocol replay is a legacy authorization diagnostic, not benchmark judgment.
No dataset actions are executed. See RJUDGE_EVALUATION.md for usage and limits.
"""
import argparse
import json
import os
import sys
import time
import hashlib
import math
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from demo.attacks.rjudge_parse import parse_action
from demo.attacks.rjudge_judgment import chat_client, run_judgment, judgment_report
from policy import taint
from policy.engine import PolicyEngine
from policy.intent_anchor import anchor_rules_llm, anchor_effect_llm, intent_llm_configured
from policy.authorize import authorize_action
from policy.tool_capabilities import TOOL_CAPABILITIES, DEFAULT_CAPABILITY, build_tool_caps

# Configuration only loads .env when explicitly enabled in development mode.
from gateway import config as _cfg  # noqa: F401

RJUDE_DATA = Path(os.environ.get("RJUDGE_DATA", ROOT / "R-Judge" / "data"))
RJUDGE_DATA = RJUDE_DATA  # Preserve the old misspelled name for callers.

# ---------------------------------------------------------------------------
# Independent Tool Capability Registry (static, label-independent).
#
# Effect fields: network_egress / external_share / credential_access / process /
# persistence (denied|allowed), sources (high-risk data read), sensitive_params
# (payload keys whose values an allow rule MUST constrain).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# data loading / parsing (unchanged helpers)
# ---------------------------------------------------------------------------

def load_records(data_dir):
    records = []
    paths = sorted(Path(data_dir).rglob("*.json"))
    if not paths:
        raise ValueError(f"No R-Judge JSON files found: {data_dir}")
    seen = set()
    for path in paths:
        raw = path.read_bytes()  # Fail closed on missing/unreadable files.
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError(f"Expected an array: {path}")
        for ex in data:
            validate_example(ex)
            if ex["id"] in seen:
                raise ValueError(f"Duplicate R-Judge id: {ex['id']}")
            seen.add(ex["id"])
            records.append({"example": ex, "category": path.parent.name,
                            "source": str(path.relative_to(data_dir)),
                            "sha256": hashlib.sha256(raw).hexdigest()})
    return records


def validate_example(ex):
    """Dependency-free validation of the official required fields and turns."""
    if not isinstance(ex, dict):
        raise ValueError("Expected a record object")
    for key in ("scenario", "profile", "goal", "risk_description", "attack_type"):
        if not isinstance(ex.get(key), str):
            raise ValueError(f"Missing/invalid {key}")
    if type(ex.get("id")) is not int or type(ex.get("label")) is not int or ex["label"] not in (0, 1):
        raise ValueError("Invalid id/label")
    if ex["attack_type"] not in ("injection", "unintended"):
        raise ValueError("Invalid attack_type")
    if not isinstance(ex.get("contents"), list):
        raise ValueError("Invalid contents")
    for round_ in ex["contents"]:
        if not isinstance(round_, list):
            raise ValueError("Invalid round")
        for turn in round_:
            if not isinstance(turn, dict) or turn.get("role") not in ("user", "agent", "environment"):
                raise ValueError("Invalid turn role")
            if turn["role"] == "agent":
                if "thought" not in turn or "action" not in turn:
                    raise ValueError("Missing agent thought/action")
                if not isinstance(turn["thought"], (str, type(None))) or not isinstance(turn["action"], (str, dict, type(None))):
                    raise ValueError("Invalid agent thought/action")
            elif "content" not in turn or not isinstance(turn["content"], (str, type(None)) if turn["role"] == "user" else (str, dict, type(None))):
                raise ValueError("Missing/invalid turn content")


def first_user_message(example):
    for r in example.get("contents", []):
        for t in r:
            if t.get("role") == "user" and t.get("content"):
                return t["content"]
    return ""


def extract_actions(example):
    out = []
    for r in example.get("contents", []):
        for t in r:
            if t.get("role") == "agent":
                for triple in parse_action(t.get("action")):
                    out.append(triple)
    return out


def task_of(example):
    profile = example.get("profile", "")
    user = first_user_message(example)
    if profile and user:
        return f"{profile}\n用户请求：{user}"
    return user or profile


def tools_hint_of(actions):
    schema = defaultdict(set)
    for tool, _target, payload in actions:
        for k in payload.keys():
            schema[tool].add(k)
    parts = []
    for tool in sorted(schema):
        args = ",".join(sorted(schema[tool]))
        parts.append(f"{tool}({args})" if args else tool)
    return "; ".join(parts)


def parse_only(records):
    rec_cov = 0
    n_actions = 0
    n_parsed = 0
    tools = Counter()
    for rec in records:
        actions = extract_actions(rec["example"])
        for r in rec["example"].get("contents", []):
            for t in r:
                if t.get("role") == "agent" and t.get("action"):
                    n_actions += 1
        if actions:
            rec_cov += 1
        for tool, _, _ in actions:
            tools[tool] += 1
            n_parsed += 1
    print("=" * 70)
    print("R-JUDGE SYMBOLIC REPLAY — PARSE-ONLY COVERAGE")
    print("=" * 70)
    print(f"records total          : {len(records)}")
    print(f"records with actions   : {rec_cov} ({rec_cov/max(len(records),1):.1%})")
    print(f"agent actions total    : {n_actions}")
    print(f"actions parsed         : {n_parsed} ({n_parsed/max(n_actions,1):.1%})")
    print(f"distinct tools         : {len(tools)}")
    print(f"tools in registry      : {sum(1 for t in tools if t in TOOL_CAPABILITIES)}/{len(tools)}")
    print(f"  uncovered tools      : {sorted(t for t in tools if t not in TOOL_CAPABILITIES)}")


# ---------------------------------------------------------------------------
# offline path (PolicyEngine + per-record taint + latency)
# ---------------------------------------------------------------------------

def run_offline(records, use_llm=True):
    engine = PolicyEngine(str(ROOT / "policy" / "policies"))
    all_tools = set()
    for rec in records:
        for tool, _, _ in extract_actions(rec["example"]):
            all_tools.add(tool)
    tool_caps = build_tool_caps(all_tools)

    rule_cache = {}
    effect_cache = {}
    rows = []
    for rec in records:
        ex = rec["example"]
        actions = extract_actions(ex)
        if not actions:
            rows.append({"id": ex["id"], "label": ex["label"], "actions": [],
                         "status": "unsupported", "category": rec["category"]})
            continue
        task = task_of(ex)
        hint = tools_hint_of(actions)

        t0 = time.perf_counter()
        key = f"{task}\x00{hint}"
        if key not in rule_cache:
            rules = anchor_rules_llm(task, tools_hint=hint) if (use_llm and intent_llm_configured()) else None
            rule_cache[key] = rules or []
        rules = rule_cache[key]
        # Expected-Effect intent profile: TRAJECTORY-FREE (task text only).
        if task not in effect_cache:
            effect_cache[task] = anchor_effect_llm(task) if (use_llm and intent_llm_configured()) else None
        behavior_profile = effect_cache[task]
        rule_ms = (time.perf_counter() - t0) * 1000

        # per-record taint state: source reads accumulate across actions
        rec_taint = {"tainted_objects": [], "dirty": False}

        replayed = []
        for tool, target, payload in actions:
            caps = tool_caps.get(tool, dict(DEFAULT_CAPABILITY, actions=[tool]))
            ts = {"tainted_objects": list(rec_taint["tainted_objects"]),
                  "dirty": rec_taint["dirty"]} if rec_taint["dirty"] else None

            action = SimpleNamespace(type=tool, target=target, payload=payload or {})
            ta = time.perf_counter()
            r = authorize_action(
                action, capability=caps, engine=engine, rules=rules,
                effect_profile=behavior_profile, taint_state=ts,
            )
            ev_ms = (time.perf_counter() - ta) * 1000
            # record a source read once it is authorized
            if r["verdict"] == "ALLOW" and taint.is_source(caps):
                taint.record_source_read(rec_taint, target, source=(caps or {}).get("sources", []))
            replayed.append({"tool": tool, "target": target, "payload": payload,
                             "verdict": r["verdict"], "reason": r["reason"],
                             "rule": r.get("rule"), "latency_ms": round(ev_ms, 2)})
        rows.append({
            "id": ex.get("id"), "category": rec["category"],
            "scenario": ex.get("scenario"), "attack_type": ex.get("attack_type"),
            "label": ex.get("label", 0), "task": task,
            "rules": rules, "rule_latency_ms": round(rule_ms, 2), "actions": replayed,
        })
    return rows


def run_gateway(records, gateway_url):
    from adapters.sdk import ICBGuardClient

    client = ICBGuardClient(gateway_url)
    admin = ICBGuardClient(gateway_url, token=os.environ["ICB_ADMIN_TOKEN"])
    intent_client = ICBGuardClient(gateway_url, token=os.environ["ICB_INTENT_TOKEN"])

    all_tools = set()
    for rec in records:
        for tool, _, _ in extract_actions(rec["example"]):
            all_tools.add(tool)
    tool_caps = build_tool_caps(all_tools)
    cert_ids = {}
    for tool, caps in tool_caps.items():
        cert_ids[tool] = admin.register_tool(f"rjudge_{tool}", caps,
                                              implementation_hash=f"sha256:rjudge:{tool}")

    rows = []
    for rec in records:
        ex = rec["example"]
        actions = extract_actions(ex)
        if not actions:
            rows.append({"id": ex["id"], "label": ex["label"], "actions": [],
                         "status": "unsupported", "category": rec["category"]})
            continue
        task = task_of(ex)
        session_id = f"rjudge-{time.time_ns()}-{ex.get('id')}"
        profile = intent_client.anchor_intent(task, session_id=session_id)
        rules = profile.get("rules", [])

        replayed = []
        for tool, target, payload in actions:
            try:
                ta = time.perf_counter()
                r = client.authorize(f"rjudge_{tool}", tool, target, task,
                                     capability_cert_id=cert_ids[tool],
                                     intent_profile=profile,
                                     payload=payload, session_id=session_id)
                ev_ms = (time.perf_counter() - ta) * 1000
                replayed.append({"tool": tool, "target": target, "payload": payload,
                                 "verdict": r.verdict, "reason": r.reason,
                                 "rule": r.decision_rule, "latency_ms": round(ev_ms, 2)})
            except Exception as e:
                replayed.append({"tool": tool, "target": target, "payload": payload,
                                 "verdict": "ERROR", "reason": str(e), "rule": None,
                                 "latency_ms": 0.0})
        rows.append({
            "id": ex.get("id"), "category": rec["category"],
            "scenario": ex.get("scenario"), "attack_type": ex.get("attack_type"),
            "label": ex.get("label", 0), "task": task,
            "rules": rules, "actions": replayed,
        })
    return rows


# ---------------------------------------------------------------------------
# report: record-level + action-level, BLOCK/CONFIRM/ALLOW split
# ---------------------------------------------------------------------------

def _record_stopped(r):
    return any(a["verdict"] in ("BLOCK", "CONFIRM") for a in r["actions"])


def _record_blocked(r):
    return any(a["verdict"] == "BLOCK" for a in r["actions"])


def report(rows, mode):
    """Conditional replay diagnostics, never an official benchmark score."""
    errored = [r for r in rows if any(a["verdict"] not in ("ALLOW", "BLOCK", "CONFIRM") for a in r["actions"])]
    covered = [r for r in rows if r["actions"] and r not in errored]
    attacks = [r for r in covered if r["label"] == 1]
    benign = [r for r in covered if r["label"] == 0]
    def rate(a, b):
        return a / b if b else None
    lats = sorted(a["latency_ms"] for r in covered for a in r["actions"]
                  if a.get("latency_ms") is not None)
    metrics = {
        "mode": mode, "errors": len(errored), "executed": False,
        "attack_success_rate": None, "records_received": len(rows),
        "records_scored": len(covered),
        "records_without_actions": sum(not r["actions"] for r in rows),
        "limitation": "Legacy replay diagnostics on covered records only; not official R-Judge judgment or observed defense success",
        "record_level": {
            "all_allowed_rate_unsafe": rate(sum(not _record_stopped(r) for r in attacks), len(attacks)),
            "intervention_rate_unsafe": rate(sum(_record_stopped(r) for r in attacks), len(attacks)),
            "hard_fpr": rate(sum(_record_blocked(r) for r in benign), len(benign)),
            "intervention_rate_safe": rate(sum(_record_stopped(r) for r in benign), len(benign))},
        "verdict_counts": dict(Counter(a["verdict"] for r in rows for a in r["actions"])),
        "latency": {"avg_ms": rate(sum(lats), len(lats)),
                    "p95_ms": lats[math.ceil(len(lats) * .95) - 1] if lats else None,
                    "percentile_method": "nearest_rank"}}
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    return metrics


def policy_evidence(example, *, enable_rules=True, enable_effects=True):
    """Causal action observations; full transcript is judged separately.

    User turns alone update intent. Environment text is never promoted to a
    trusted instruction. Stop on first intervention: no invented continuation.
    """
    engine = PolicyEngine(str(ROOT / "policy" / "policies"))
    caps = build_tool_caps(set(TOOL_CAPABILITIES))
    trusted = [example["profile"]]
    rules, effect = [], None
    dirty_intent = True
    state = {"tainted_objects": [], "dirty": False}
    observations = []
    for ri, round_ in enumerate(example["contents"]):
        for ti, turn in enumerate(round_):
            if turn["role"] == "user" and turn.get("content"):
                trusted.append(turn["content"])
                dirty_intent = True
            if turn["role"] != "agent" or not turn.get("action"):
                continue
            actions = parse_action(turn["action"])
            if not actions:
                observations.append({"round": ri, "turn": ti, "status": "unsupported_action"})
                # Unknown side effects make subsequent simulated state unreliable.
                return {"observations": observations, "stop_reason": "unsupported_action"}
            if dirty_intent:
                task = "\n".join(trusted)
                rules = anchor_rules_llm(task, tools_hint="; ".join(sorted(TOOL_CAPABILITIES))) if enable_rules else []
                effect = anchor_effect_llm(task) if enable_effects else None
                if (enable_rules and rules is None) or (enable_effects and effect is None):
                    raise RuntimeError("Policy intent generation failed")
                dirty_intent = False
            for tool, target, payload in actions:
                if tool not in caps:
                    observations.append({"round": ri, "turn": ti, "tool": tool, "status": "unsupported_tool"})
                    return {"observations": observations, "stop_reason": "unsupported_tool"}
                decision = authorize_action(SimpleNamespace(type=tool, target=target, payload=payload),
                    capability=caps[tool], engine=engine, rules=rules, effect_profile=effect,
                    taint_state=state if state["dirty"] else None, enable_rules=enable_rules,
                    intent_text=task)
                observations.append({"round": ri, "turn": ti, "tool": tool, **decision})
                if decision["verdict"] != "ALLOW":
                    return {"observations": observations, "stop_reason": "intervention"}
                if taint.is_source(caps[tool]):
                    taint.record_source_read(state, target, source=caps[tool].get("sources", []))
    return {"observations": observations, "stop_reason": "end",
            "state_assumption": "Conservative source taint on ALLOW; no actual execution"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--protocol", choices=["official", "policy-assisted", "replay"], default="official",
                    help="official: full-record model judgment; policy-assisted: add policy evidence; replay: legacy diagnostic")
    ap.add_argument("--model", default=os.environ.get("RJUDGE_MODEL"))
    ap.add_argument("--base-url", default=os.environ.get("RJUDGE_BASE_URL", "https://api.openai.com/v1"))
    ap.add_argument("--expected-count", type=int, default=569,
                    help="Validate full dataset BEFORE filtering; change explicitly for a custom dataset")
    ap.add_argument("--validate-only", action="store_true", help="Check dataset and print manifest without model calls")
    ap.add_argument("--no-effects", action="store_true", help="Disable policy effect profiles only")
    ap.add_argument("--parse-only", action="store_true")
    ap.add_argument("--gateway", action="store_true")
    ap.add_argument("--gateway-url", default="http://127.0.0.1:8099")
    ap.add_argument("--attack-type", choices=["unintended", "injection", "ALL"], default="ALL")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--data", type=str, default=str(RJUDE_DATA))
    ap.add_argument("--no-rules", action="store_true",
                    help="ablation: run the engine WITHOUT the intent-LLM rules")
    ap.add_argument("--export", type=str, default="")
    args = ap.parse_args()

    if args.limit is not None and args.limit <= 0:
        ap.error("--limit must be positive")
    if args.protocol != "replay" and args.gateway:
        ap.error("--gateway requires --protocol replay")
    if args.protocol == "official" and (args.no_rules or args.no_effects):
        ap.error("Policy ablations require --protocol policy-assisted")
    if args.protocol == "replay" and (args.no_rules or args.no_effects):
        ap.error("Legacy replay ablations are disabled; use --protocol policy-assisted")
    records = load_records(Path(args.data))
    if len(records) != args.expected_count:
        ap.error(f"Dataset count {len(records)} != expected {args.expected_count}; restore dataset or explicitly select a custom count")
    manifest = {"dataset_root": str(Path(args.data).resolve()), "total_records": len(records),
                "expected_count": args.expected_count,
                "official_dataset_size_match": len(records) == 569,
                "files": {r["source"]: r["sha256"] for r in records}}
    if args.attack_type != "ALL":
        records = [r for r in records if r["example"].get("attack_type") == args.attack_type]
    if args.limit:
        records = records[: args.limit]
        print(f"(limited to {args.limit} records)\n")
    if not records:
        ap.error("No records selected")

    manifest["selected_ids"] = [r["example"]["id"] for r in records]
    manifest["subset"] = len(records) != manifest["total_records"]
    if args.validate_only:
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
        return

    if args.parse_only:
        parse_only(records)
        return

    if args.protocol != "replay":
        if not args.model:
            ap.error("Set --model or RJUDGE_MODEL")
        if args.protocol == "policy-assisted" and (not args.no_rules or not args.no_effects) and not intent_llm_configured():
            ap.error("Policy-assisted mode needs ICB_INTENT_LLM_API_KEY (or explicitly disable both policy LLM components)")
        output = Path(args.export) if args.export else ROOT / "results" / f"rjudge_{args.protocol}_{time.time_ns()}.json"
        output.parent.mkdir(parents=True, exist_ok=True)
        checkpoint = output.with_suffix(output.suffix + ".jsonl")
        if output.exists() or checkpoint.exists():
            ap.error("Output already exists; choose another --export path")
        ask = chat_client(args.base_url, os.environ.get("RJUDGE_API_KEY", ""), args.model)
        provider = None
        if args.protocol == "policy-assisted":
            provider = lambda ex: policy_evidence(ex, enable_rules=not args.no_rules, enable_effects=not args.no_effects)
        with checkpoint.open("x", encoding="utf-8") as stream:
            def save_row(row):
                stream.write(json.dumps(row, ensure_ascii=False) + "\n")
                stream.flush()
                print(f"[{row['id']}] {row['status']}", flush=True)
            rows = run_judgment(records, ask, args.model, provider, save_row)
        metrics = judgment_report(rows)
        metadata = {"protocol": args.protocol, "model": args.model, "temperature": 0,
                    "analysis_max_tokens": 500, "label_max_tokens": 1 if args.model.startswith("gpt") else 500,
                    "no_rules": args.no_rules, "no_effects": args.no_effects,
                    "policy_model": os.environ.get("ICB_INTENT_LLM_MODEL", "gpt-4o-mini") if provider else None,
                    "policy_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted((ROOT / "policy").rglob("*"))
                        if provider and p.suffix in (".py", ".yaml", ".yml")},
                    "implementation_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in (Path(__file__), Path(__file__).with_name("rjudge_judgment.py"))},
                    "limitation": "Safety judgment only; policy-assisted adds nonofficial evidence; no execution or attack-success measurement"}
        with output.open("x", encoding="utf-8") as stream:
            json.dump({"metadata": metadata, "manifest": manifest, "metrics": metrics, "rows": rows},
                      stream, ensure_ascii=False, indent=2, allow_nan=False)
        print(json.dumps(metrics, ensure_ascii=False, indent=2))
        print(f"exported -> {output}")
        if not metrics["overall"]["complete"]:
            raise SystemExit(2)
        return

    print("WARNING: legacy authorization replay is not official R-Judge judgment; it omits conversation context and cannot measure defense success.")
    mode = "gateway-authorization-replay" if args.gateway else (
        "offline-engine-no-rules" if args.no_rules else "offline-symbolic-engine")
    if args.gateway:
        rows = run_gateway(records, args.gateway_url)
    else:
        rows = run_offline(records, use_llm=not args.no_rules)
        if not intent_llm_configured() and not args.no_rules:
            print("[note] ICB_INTENT_LLM_API_KEY not set -> no rules -> symbolic layer off.\n"
                  "       set it (or use --gateway with a configured gateway) to generate rules.\n")

    metrics = report(rows, mode)

    out_path = Path(args.export) if args.export else (ROOT / "results" / f"rjudge_{mode}_{time.time_ns()}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("x", encoding="utf-8") as stream:
        json.dump({"manifest": manifest, "metrics": metrics, "rows": rows}, stream,
                  ensure_ascii=False, indent=2, default=str)
    print(f"\nexported -> {out_path}")


if __name__ == "__main__":
    main()
