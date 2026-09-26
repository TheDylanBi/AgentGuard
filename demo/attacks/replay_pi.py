"""Replay attack samples through pi's tool-call adapter layer (P5 deployment).

Simulates what pi_extension.ts does: map a pi tool call to a gateway action,
authorize, and report whether pi would BLOCK / CONFIRM / ALLOW.

Mapping (mirrors pi_extension.ts):
  bash  -> shell      read  -> read_file
  write -> write_file  gui_click -> click (screenshot only, like the extension)

Attack samples whose action has no pi equivalent (type/upload/download) are
marked N/A.

Run (after the gateway is up):
  python demo/attacks/replay_pi.py [--limit N]
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from adapters.sdk import ICBGuardClient

GATEWAY = os.environ.get("ICB_GATEWAY_URL", "http://127.0.0.1:8099")
DATA = Path(__file__).resolve().parent / "data"
IMG_DIR = DATA / "images"

READ_GLOBS = [g.strip() for g in os.environ.get("ICB_READ_GLOBS", "/workspace/*").split(",")]
WRITE_GLOBS = [g.strip() for g in os.environ.get("ICB_WRITE_GLOBS", "/workspace/*").split(",")]

# identical to what pi_extension.ts registers
PI_AGENT_CAPS = {
    "actions": ["shell", "read_file", "write_file", "click"],
    "filesystem_read": READ_GLOBS,
    "filesystem_write": WRITE_GLOBS,
    "network": "denied", "credential": "denied", "process": "allowed", "persistence": "denied",
}

# sample action type -> pi built-in/custom tool
PI_TOOL = {
    "shell": "bash",
    "read_file": "read",
    "write_file": "write",
    "click": "gui_click",
}
# type / upload / download -> no pi tool equivalent


def main():
    client = ICBGuardClient(GATEWAY)
    cert_id = client.register_tool("pi_agent", PI_AGENT_CAPS,
                                   implementation_hash="sha256:pi-agent")

    samples = json.loads((DATA / "samples.json").read_text(encoding="utf-8"))
    if "--limit" in sys.argv:
        samples = samples[: int(sys.argv[sys.argv.index("--limit") + 1])]

    rows = []
    for s in samples:
        action = s["action"]["type"]
        pi_tool = PI_TOOL.get(action)
        if pi_tool is None:
            rows.append({"id": s["id"], "action": action, "pi_tool": "N/A", "verdict": "-"})
            continue

        vs = s["visual_state"]
        # fixed extension: gui_click now sends screenshot + a11y snapshot (role check)
        img = IMG_DIR / vs["image"] if (pi_tool == "gui_click" and vs.get("image")) else None
        a11y = vs.get("a11y_snapshot") if pi_tool == "gui_click" else None
        r = client.authorize(
            "pi_agent", action, s["action"]["target"], s["intent_anchor"],
            capability_cert_id=cert_id,
            screenshot_path=img,
            a11y_snapshot=a11y,
        )
        rows.append({"id": s["id"], "action": action, "pi_tool": pi_tool, "verdict": r.verdict})

    # ---- report ----
    attacks = [r for r in rows if r["verdict"] != "-"]
    na = [r for r in rows if r["verdict"] == "-"]
    blocked = [r for r in attacks if r["verdict"] != "ALLOW"]
    slipped = [r for r in attacks if r["verdict"] == "ALLOW"]

    print("=" * 72)
    print("PI ADAPTER REPLAY REPORT")
    print("=" * 72)
    print(f"{'sample':<42}{'action':<12}{'pi_tool':<10}{'verdict'}")
    for r in rows:
        print(f"{r['id']:<42}{r['action']:<12}{r['pi_tool']:<10}{r['verdict']}")
    print()

    print(f"mapped to pi tools : {len(attacks)}")
    print(f"  blocked/confirmed: {len(blocked)}")
    print(f"  slipped (ALLOW)  : {len(slipped)}")
    print(f"no pi equivalent   : {len(na)} (type/upload/download)")
    if slipped:
        print("\nSLIPPED (would run in pi):")
        for r in slipped:
            print(f"  {r['id']} ({r['pi_tool']})")


if __name__ == "__main__":
    main()
