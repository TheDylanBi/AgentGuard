"""End-to-end test of the symbolic least-privilege layer (P0-P3).

Requires the gateway to be running (start with the intent LLM disabled for a
deterministic run):

    ICB_INTENT_LLM_API_KEY= python -m gateway.main        # terminal 1
    python tests/test_gateway_e2e.py                      # terminal 2

Exercises, through the real /authorize + /confirm endpoints:
  - sink tool (network egress): specific-allow -> ALLOW; deny -> BLOCK;
    outside -> CONFIRM (semantic gap, with approval rule).
  - non-sink tool: outside -> CONFIRM + policy_update (expansion), approving it
    merges the rule server-side (runtime evolution), the same action -> ALLOW.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from adapters.sdk import ICBGuardClient
from attestation.signer import Signer
from gateway.api_schema import IntentProfile, PolicyRule, RulePredicate
from gateway.config import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

GATEWAY = os.environ.get("ICB_GATEWAY_URL", "http://127.0.0.1:8099")

# sink tool: network + credential egress, sensitive param declared
EMAIL_CAPS = {
    "actions": ["email"],
    "filesystem_read": [], "filesystem_write": [],
    "network": "allowed", "credential": "allowed",
    "process": "denied", "persistence": "denied",
    "sensitive_params": ["payload.to"],
}
# non-sink tool: no egress, sensitive param declared
NOTES_CAPS = {
    "actions": ["notes"],
    "filesystem_read": [], "filesystem_write": [],
    "network": "denied", "credential": "denied",
    "process": "denied", "persistence": "denied",
    "sensitive_params": ["payload.note_id"],
}

_PASS = 0
_FAIL = 0


def check(name, cond, extra=""):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS  {name}")
    else:
        _FAIL += 1
        print(f"  FAIL  {name}  {extra}")


def signed_profile(intent_text, tool, field, value):
    signer = Signer(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    profile = IntentProfile(
        intent_text=intent_text,
        rules=[PolicyRule(tool=tool, decision="allow",
                          predicate=RulePredicate(op="eq", field=field, value=value))],
    )
    payload = profile.model_dump(exclude={"signature"})
    profile.signature = signer.sign(payload)
    return profile


def main():
    client = ICBGuardClient(GATEWAY)
    try:
        health = client.health()
    except Exception as e:
        sys.exit(f"[fatal] gateway unreachable at {GATEWAY}: {e}")
    print(f"gateway: {GATEWAY}  intent_llm: {health.get('intent_llm')}\n")

    email_cert = client.register_tool("email_agent", EMAIL_CAPS, implementation_hash="sha256:email")
    notes_cert = client.register_tool("notes_agent", NOTES_CAPS, implementation_hash="sha256:notes")
    email_profile = signed_profile("email alice only", "email", "payload.to", "alice@company.com")
    notes_profile = signed_profile("read note n1 only", "notes", "payload.note_id", "n1")

    # ---- sink tool ----
    print("[sink tool: email]")
    def email(to):
        return client.authorize("email_agent", "email", "send", email_profile.intent_text,
                                capability_cert_id=email_cert,
                                intent_profile=email_profile.model_dump(),
                                payload={"to": to}, session_id="e2e-email")

    r = email("alice@company.com")
    check("specific-allow -> ALLOW", r.verdict == "ALLOW", f"{r.verdict}: {r.reason}")

    r = email("carol@x.com")
    check("outside -> CONFIRM (semantic gap, sink)", r.verdict == "CONFIRM", f"{r.verdict}: {r.reason}")
    check("outside carries policy_update (sink)", r.policy_update is not None, str(r.policy_update))

    # ---- non-sink tool: expansion -> approval -> evolution ----
    print("[non-sink tool: notes]")
    def notes(nid):
        return client.authorize("notes_agent", "notes", "read", notes_profile.intent_text,
                                capability_cert_id=notes_cert,
                                intent_profile=notes_profile.model_dump(),
                                payload={"note_id": nid}, session_id="e2e-notes")

    r = notes("n1")
    check("specific-allow -> ALLOW", r.verdict == "ALLOW", f"{r.verdict}: {r.reason}")

    r = notes("n2")
    check("outside -> CONFIRM", r.verdict == "CONFIRM", f"{r.verdict}: {r.reason}")
    check("carries policy_update", r.policy_update is not None, str(r.policy_update))
    check("carries confirm_token", bool(r.confirm_token), str(r.confirm_token))

    resp = client.confirm(r.confirm_token, approve=True)
    check("confirm approve", resp.get("status") == "approved", str(resp))

    r2 = notes("n2")
    check("after approval -> ALLOW (monotonic evolution)", r2.verdict == "ALLOW",
          f"{r2.verdict}: {r2.reason}")

    r3 = notes("n3")
    check("different note still CONFIRM", r3.verdict == "CONFIRM", f"{r3.verdict}: {r3.reason}")

    print(f"\n{'=' * 60}\nRESULT: {_PASS} passed, {_FAIL} failed\n{'=' * 60}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
