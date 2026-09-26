"""P6 evaluation + result export.

Loads demo/attacks/data/samples.json, runs every sample against the gateway,
prints a report, and exports results to ICB_RESULT_DIR (default F:/Code/result).

Run (after the gateway is up):
  python demo/attacks/eval.py
"""
import csv
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from adapters.sdk import ICBGuardClient

GATEWAY = os.environ.get("ICB_GATEWAY_URL", "http://127.0.0.1:8099")
RESULT_DIR = Path(os.environ.get("ICB_RESULT_DIR", "F:/Code/result"))
DATA = Path(__file__).resolve().parent / "data"
IMG_DIR = DATA / "images"


def run_sample(client: ICBGuardClient, s: dict):
    cert_id = None
    reg = s.get("register")
    if reg:
        cert_id = client.register_tool(
            s["tool_id"], reg["capabilities"],
            implementation_hash=reg.get("implementation_hash"),
        )
    re_reg = s.get("re_register")
    if re_reg:
        cert_id = client.register_tool(
            s["tool_id"], re_reg["capabilities"],
            implementation_hash=re_reg.get("implementation_hash"),
            force=True,
        )

    vs = s["visual_state"]
    image = IMG_DIR / vs["image"] if vs.get("image") else None
    prev_image = IMG_DIR / vs["previous_image"] if vs.get("previous_image") else None

    t0 = time.perf_counter()
    r = client.authorize(
        s["tool_id"], s["action"]["type"], s["action"]["target"], s["intent_anchor"],
        capability_cert_id=cert_id,
        screenshot_path=image,
        a11y_snapshot=vs.get("a11y_snapshot"),
        previous_screenshot_path=prev_image,
        previous_a11y_snapshot=vs.get("previous_a11y_snapshot"),
        session_id=s["id"],
    )
    dt = time.perf_counter() - t0
    return {
        "id": s["id"],
        "category": s["category"],
        "verdict": r.verdict,
        "reason": r.reason,
        "ground_truth": s["ground_truth"],
        "expected": s["expected_failure_point"],
        "latency_ms": round(dt * 1000, 1),
        "ok": (s["category"] == "attack" and r.verdict != "ALLOW")
              or (s["category"] == "benign" and r.verdict == "ALLOW"),
    }


def export(results, metrics, attribution, slipped):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")

    summary = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "gateway": GATEWAY,
        "metrics": metrics,
        "attribution": attribution,
        "limitations": slipped,
        "samples": results,
    }

    def _safe_write(path, text):
        try:
            path.write_text(text, encoding="utf-8")
            return path
        except OSError:
            alt = path.with_name(f"{path.stem}_{ts}{path.suffix}")
            alt.write_text(text, encoding="utf-8")
            return alt

    jp = _safe_write(RESULT_DIR / "results.json",
                     json.dumps(summary, ensure_ascii=False, indent=2))

    csv_buf = []
    fieldnames = ["id", "category", "verdict", "ground_truth", "expected", "latency_ms", "ok"]
    csv_buf.append(",".join(fieldnames))
    for r in results:
        csv_buf.append(",".join(str(r.get(k, "")) for k in fieldnames))
    cp = _safe_write(RESULT_DIR / "results.csv",
                     "\ufeff" + "\n".join(csv_buf) + "\n")

    print(f"\nexported -> {jp}")
    print(f"exported -> {cp}")


def main():
    client = ICBGuardClient(GATEWAY)
    samples = json.loads((DATA / "samples.json").read_text(encoding="utf-8"))

    if "--limit" in sys.argv:
        n = int(sys.argv[sys.argv.index("--limit") + 1])
        samples = samples[:n]
        print(f"(limited to {n} samples)\n")

    results = [run_sample(client, s) for s in samples]
    attacks = [x for x in results if x["category"] == "attack"]
    benign = [x for x in results if x["category"] == "benign"]

    asr = sum(1 for x in attacks if x["verdict"] == "ALLOW") / max(len(attacks), 1)
    fpr = sum(1 for x in benign if x["verdict"] == "BLOCK") / max(len(benign), 1)
    avg_lat = sum(x["latency_ms"] for x in results) / max(len(results), 1)

    attribution = {}
    for x in attacks:
        if x["verdict"] != "ALLOW":
            attribution[x["expected"]] = attribution.get(x["expected"], 0) + 1

    slipped = [x["id"] for x in attacks if x["verdict"] == "ALLOW"]

    print("=" * 78)
    print("ICB-GUARD P6 EVALUATION REPORT")
    print("=" * 78)
    print(f"{'sample':<14}{'category':<9}{'verdict':<9}{'gt':<9}{'pillar':<8}{'lat(ms)':<9}ok")
    for x in results:
        print(f"{x['id']:<14}{x['category']:<9}{x['verdict']:<9}"
              f"{x['ground_truth']:<9}{str(x['expected']):<8}{x['latency_ms']:<9}"
              f"{'OK' if x['ok'] else 'FAIL'}")
    print()

    print(f"attacks: {len(attacks)}   benign: {len(benign)}")
    print(f"ASR (attack success rate)    = {asr * 100:.1f}%  "
          f"({sum(1 for x in attacks if x['verdict'] == 'ALLOW')}/{len(attacks)} got through)")
    print(f"Defense rate                 = {(1 - asr) * 100:.1f}%")
    print(f"FPR (benign wrongly blocked) = {fpr * 100:.1f}%")
    print(f"Avg latency                  = {avg_lat:.1f} ms")
    print()
    print("Attribution (attacks stopped by pillar):")
    for k in sorted(attribution, key=str):
        print(f"  {k}: {attribution[k]}")
    if slipped:
        print()
        print("LIMITATION (attacks that slipped through -> future work):", slipped)

    metrics = {
        "attacks": len(attacks),
        "benign": len(benign),
        "asr": round(asr, 4),
        "defense_rate": round(1 - asr, 4),
        "fpr": round(fpr, 4),
        "avg_latency_ms": round(avg_lat, 1),
    }
    export(results, metrics, attribution, slipped)


if __name__ == "__main__":
    main()
