"""Tests for the multi-turn intent-inflation guard (revoke-on-new-input).

Unit-level: exercises the server-side epoch / reset / stale-token logic
directly (no gateway process needed):

    python tests/test_epoch_revoke.py

HTTP-level (needs the gateway running):

    python tests/test_epoch_revoke.py --gateway
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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


def _allow_email(addr):
    return {"tool": "email", "decision": "allow",
            "predicate": {"op": "eq", "field": "payload.to", "value": addr}}


def test_unit():
    import gateway.server as gs

    # reset module state for a clean run
    gs.SESSION_POLICIES.clear()
    gs.SESSION_EPOCHS.clear()
    gs.PENDING_CONFIRMS.clear()

    print("\n[unit: revoke-on-new-input]")

    # turn 1: seed policy (simulating /authorize seeding), issue a token
    gs.SESSION_POLICIES["s1"] = {"rules": [_allow_email("alice@x.com")]}
    gs.SESSION_EPOCHS["s1"] = 0
    tok1 = gs._issue_confirm_token("s1", "cert1", policy_update={"rule": _allow_email("carol@x.com")})
    check("token1 carries epoch 0", gs.PENDING_CONFIRMS[tok1]["epoch"] == 0)

    # turn 2: new anchor -> revoke + bump epoch
    gs._reset_session_policy("s1", {"rules": [_allow_email("bob@x.com")]})
    check("epoch bumped to 1", gs.SESSION_EPOCHS["s1"] == 1)
    check("policy replaced (not unioned)",
          len(gs.SESSION_POLICIES["s1"]["rules"]) == 1 and
          gs.SESSION_POLICIES["s1"]["rules"][0]["predicate"]["value"] == "bob@x.com")

    # stale token from turn 1 must NOT apply in turn 2
    payload1 = gs.PENDING_CONFIRMS[tok1]
    is_stale = payload1.get("epoch", -1) != gs.SESSION_EPOCHS.get(payload1["session_id"], 0)
    check("turn1 token is stale after re-anchor", is_stale is True)

    # a fresh token issued in turn 2 applies cleanly
    tok2 = gs._issue_confirm_token("s1", "cert2", policy_update={"rule": _allow_email("dave@x.com")})
    check("token2 carries epoch 1", gs.PENDING_CONFIRMS[tok2]["epoch"] == 1)
    gs._apply_policy_update("s1", gs.PENDING_CONFIRMS[tok2]["policy_update"])
    values = {r["predicate"].get("value") for r in gs.SESSION_POLICIES["s1"]["rules"]}
    check("fresh expansion applied", "dave@x.com" in values, str(values))

    # session isolation: another session's policy is independent
    gs.SESSION_POLICIES["s2"] = {"rules": [_allow_email("eve@x.com")]}
    check("sessions isolated", gs.SESSION_POLICIES["s2"]["rules"][0]["predicate"]["value"] == "eve@x.com"
          and gs.SESSION_POLICIES["s1"]["rules"][0]["predicate"]["value"] == "bob@x.com")


def test_http():
    import os
    from adapters.sdk import ICBGuardClient
    from attestation.signer import Signer
    from gateway.api_schema import IntentProfile, PolicyRule, RulePredicate
    from gateway.config import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

    gateway = os.environ.get("ICB_GATEWAY_URL", "http://127.0.0.1:8099")
    client = ICBGuardClient(gateway)
    try:
        client.health()
    except Exception as e:
        print(f"[skip http] gateway unreachable: {e}")
        return

    signer = Signer(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    # non-sink tool so "outside" -> CONFIRM (sink tools get hard BLOCK now)
    cert_id = client.register_tool("epoch_agent",
                                   {"actions": ["notes"], "network": "denied",
                                    "credential": "denied", "process": "denied",
                                    "filesystem_read": [], "filesystem_write": [],
                                    "persistence": "denied",
                                    "sensitive_params": ["payload.note_id"]},
                                   implementation_hash="sha256:epoch")

    def signed(note_id):
        # only an allow rule -> a DIFFERENT note is "outside" the policy
        # (expansion -> CONFIRM), which is what the stale-token test needs.
        p = IntentProfile(intent_text=f"only {note_id}", rules=[
            PolicyRule(tool="notes", decision="allow",
                       predicate=RulePredicate(op="eq", field="payload.note_id", value=note_id)),
        ])
        payload = p.model_dump(exclude={"signature"})
        p.signature = signer.sign(payload)
        return p

    print("\n[http: revoke-on-new-input]")
    import time as _time
    session = f"epoch-http-{int(_time.time() * 1000)}"

    # turn 1: seed via authorize (note n1 allowed), then request expansion (n2)
    p1 = signed("n1")
    r = client.authorize("epoch_agent", "notes", "read", p1.intent_text,
                         capability_cert_id=cert_id, intent_profile=p1.model_dump(),
                         payload={"note_id": "n2"}, session_id=session)
    check("turn1 expansion -> CONFIRM", r.verdict == "CONFIRM", r.verdict)
    tok = r.confirm_token

    # turn 2: re-anchor (revoke). Use a direct POST so the SAME session_id is
    # used (the SDK's anchor_intent() helper hardcodes session_id="sdk").
    import requests
    requests.post(f"{gateway}/anchor_intent",
                  json={"session_id": session, "prompt": "a completely different task"},
                  timeout=30).raise_for_status()

    # stale confirm from turn 1 must be rejected
    resp = client.confirm(tok, approve=True)
    check("stale confirm rejected", resp.get("status") == "stale", str(resp))


def main():
    test_unit()
    if "--gateway" in sys.argv:
        test_http()
    print(f"\n{'=' * 60}\nRESULT: {_PASS} passed, {_FAIL} failed\n{'=' * 60}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
