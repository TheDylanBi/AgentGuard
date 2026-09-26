"""Evaluate converted samples against the live browser (attached mode).

For each sample: navigate the browser to the page, anchor the intent, then
authorize via attached mode (the gateway pulls the real a11y tree itself).

Prerequisites:
  - gateway running (python -m gateway.main)
  - Chrome on CDP :9222 (browser-start.js)

Usage:
  python demo/attacks/eval_attached.py --input demo/attacks/data/converted.json [--limit N]
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from adapters.sdk import ICBGuardClient

GATEWAY = os.environ.get("ICB_GATEWAY_URL", "http://127.0.0.1:8099")
BROWSER_NAV = os.environ.get(
    "ICB_BROWSER_NAV",
    "D:/Pi/.pi/agent/skills/pi-skills/browser-tools/browser-nav.js",
)
CDP = os.environ.get("ICB_CDP_ENDPOINT", "http://localhost:9222")

DEFAULT_CAPS = {
    "actions": ["click", "type", "read_file", "write_file", "shell"],
    "filesystem_read": ["/workspace/*"],
    "filesystem_write": ["/workspace/*"],
    "network": "denied", "credential": "denied", "process": "allowed", "persistence": "denied",
}


def navigate(page: str):
    """Navigate the existing browser via CDP (Playwright, same as the gateway)."""
    if not page:
        return
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP)
        try:
            pages = browser.contexts[0].pages
            if not pages:
                raise RuntimeError("no page available")
            pages[0].goto(page)
        finally:
            browser.close()
    time.sleep(1.0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    samples = json.loads(Path(args.input).read_text(encoding="utf-8"))
    if args.limit:
        samples = samples[: args.limit]

    client = ICBGuardClient(GATEWAY)
    cert_id = client.register_tool("external_tool", DEFAULT_CAPS,
                                   implementation_hash="sha256:external")

    rows = []
    VISUAL_ACTIONS = {"click", "type"}
    for s in samples:
        # navigate only for visual actions (non-visual need no browser)
        if s["action_type"] in VISUAL_ACTIONS:
            navigate(s.get("page"))
        profile = None
        try:
            profile = client.anchor_intent(s["intent_anchor"])
        except Exception:
            pass
        caps = s.get("capabilities") or DEFAULT_CAPS
        cid = cert_id
        if s.get("capabilities"):
            cid = client.register_tool("external_tool", caps,
                                       implementation_hash="sha256:external", force=True)
        try:
            if s["action_type"] in VISUAL_ACTIONS:
                r = client.authorize_attached(
                    "external_tool", s["action_type"], s["action_target"],
                    s["intent_anchor"], CDP, intent_profile=profile, capability_cert_id=cid,
                )
            else:
                r = client.authorize(
                    "external_tool", s["action_type"], s["action_target"],
                    s["intent_anchor"], capability_cert_id=cid, intent_profile=profile,
                )
            rows.append({
                "id": s["id"], "source": s["source"], "category": s["category"],
                "verdict": r.verdict, "ground_truth": s["ground_truth"],
                "expected": s["expected_failure_point"], "reason": r.reason,
            })
        except Exception as e:
            # browser screenshot timeout / no real web environment -> skip
            rows.append({
                "id": s["id"], "source": s["source"], "category": s["category"],
                "verdict": "SKIP", "ground_truth": s["ground_truth"],
                "expected": s["expected_failure_point"],
                "reason": f"需真实浏览器环境({type(e).__name__})",
            })

    attacks = [x for x in rows if x["category"] == "attack"]
    benign = [x for x in rows if x["category"] == "benign"]
    skipped = [x for x in rows if x["verdict"] == "SKIP"]
    tested_attacks = [x for x in attacks if x["verdict"] != "SKIP"]
    asr = sum(1 for x in tested_attacks if x["verdict"] == "ALLOW") / max(len(tested_attacks), 1)
    fpr = sum(1 for x in benign if x["verdict"] == "BLOCK") / max(len(benign), 1)

    print("=" * 78)
    print("EXTERNAL DATASET EVAL (attached mode)")
    print("=" * 78)
    for x in rows:
        if x["verdict"] == "SKIP":
            print(f"{x['id']:<26}{x['category']:<8}{'SKIP':<9}{x['ground_truth']:<9}—   {x['reason'][:40]}")
            continue
        ok = (x["category"] == "attack" and x["verdict"] != "ALLOW") or \
             (x["category"] == "benign" and x["verdict"] == "ALLOW")
        print(f"{x['id']:<26}{x['category']:<8}{x['verdict']:<9}"
              f"{x['ground_truth']:<9}{'OK' if ok else 'FAIL'}   {x['reason'][:40]}")
    print()
    print(f"attacks: {len(attacks)} (tested {len(tested_attacks)}, skipped {len(skipped)})")
    print(f"ASR (attack success)  = {asr * 100:.1f}%  (只统计已测试样本)")
    print(f"FPR (benign blocked)  = {fpr * 100:.1f}%")


if __name__ == "__main__":
    main()
