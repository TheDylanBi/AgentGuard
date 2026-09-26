"""Item-7 feedback-loop tests: generalized rules + escalation budget.

Unit tests (no gateway):

    python tests/test_feedback_loop.py

Gateway integration (needs gateway running):

    python tests/test_feedback_loop.py --gateway
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from policy.symbolic import (
    action_fields, predicate_holds, predicate_fields,
    make_generalized_rule, normalize_sensitive_fields, classify_update,
)

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


def test_normalize():
    print("\n[normalize_sensitive_fields]")
    r = normalize_sensitive_fields(["to", "cc", "target", "payload.x", "type"])
    check("bare keys -> payload.*", r == ["payload.to", "payload.cc", "target", "payload.x", "type"], str(r))


def test_generalized_rule():
    print("\n[make_generalized_rule: two-level granularity]")
    fields = action_fields("gmail_send_email", "send",
                           {"to": "alice@company.com", "subject": "meeting notes", "body": "hi"})
    rule = make_generalized_rule("gmail_send_email", fields,
                                 sensitive_fields=["payload.to"], decision="allow")

    pf = predicate_fields(rule["predicate"])
    check("pins sensitive to", "payload.to" in pf, str(pf))
    check("relaxes subject", "payload.subject" not in pf, str(pf))
    check("relaxes body", "payload.body" not in pf, str(pf))
    check("decision allow", rule["decision"] == "allow")

    # same recipient, different subject -> still matches (no re-confirm)
    f2 = action_fields("gmail_send_email", "send",
                       {"to": "alice@company.com", "subject": "completely different", "body": "..."})
    check("same recipient, different detail -> matches", predicate_holds(rule["predicate"], f2))

    # different recipient -> NOT matched
    f3 = action_fields("gmail_send_email", "send", {"to": "bob@company.com", "subject": "meeting notes"})
    check("different recipient -> not matched", not predicate_holds(rule["predicate"], f3))

    # deny rule: decision flipped + narrowing
    deny = make_generalized_rule("gmail_send_email", fields,
                                 sensitive_fields=["payload.to"], decision="deny")
    check("deny decision", deny["decision"] == "deny")
    check("new deny is narrowing", classify_update(deny, []) == "narrowing")

    # shell: command pinned (target + payload.command)
    sh = action_fields("shell", "rm -rf /", {"command": "rm -rf /"})
    r2 = make_generalized_rule("shell", sh, sensitive_fields=["payload.command"])
    pf2 = predicate_fields(r2["predicate"])
    check("shell pins command", "payload.command" in pf2 or "target" in pf2, str(pf2))


def test_gateway():
    import os
    import time as _time
    from adapters.sdk import ICBGuardClient
    from attestation.signer import Signer
    from gateway.api_schema import IntentProfile, PolicyRule, RulePredicate
    from gateway.config import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

    gateway = os.environ.get("ICB_GATEWAY_URL", "http://127.0.0.1:8099")
    client = ICBGuardClient(gateway)
    try:
        client.health()
    except Exception as e:
        print(f"[skip gateway] unreachable: {e}")
        return

    signer = Signer(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    cert = client.register_tool("fb_agent", {
        "actions": ["notes"], "network": "denied", "credential": "denied",
        "process": "denied", "persistence": "denied",
        "filesystem_read": [], "filesystem_write": [],
        "sensitive_params": ["payload.note_id"],
    }, implementation_hash="sha256:fb")

    def signed(nid):
        p = IntentProfile(intent_text=f"read {nid}", rules=[
            PolicyRule(tool="notes", decision="allow",
                       predicate=RulePredicate(op="eq", field="payload.note_id", value=nid))])
        pl = p.model_dump(exclude={"signature"})
        p.signature = signer.sign(pl)
        return p

    session = f"fb-{int(_time.time()*1000)}"
    p = signed("n1")

    def read(nid):
        return client.authorize("fb_agent", "notes", "read", p.intent_text,
                                capability_cert_id=cert, intent_profile=p.model_dump(),
                                payload={"note_id": nid}, session_id=session)

    print("\n[gateway: feedback loop]")
    r = read("n2")  # outside -> CONFIRM + generalized allow rule
    check("outside -> CONFIRM", r.verdict == "CONFIRM", r.verdict)
    tok = r.confirm_token

    # approve -> generalized allow rule (note_id=n2) merged
    resp = client.confirm(tok, approve=True)
    check("approve", resp.get("status") == "approved", str(resp))
    r2 = read("n2")
    check("same action after approve -> ALLOW", r2.verdict == "ALLOW", f"{r2.verdict}: {r2.reason}")
    r3 = read("n3")
    check("different note still CONFIRM (not over-generalized)", r3.verdict == "CONFIRM", r3.verdict)

    # reject -> narrowing deny rule
    resp = client.confirm(r3.confirm_token, approve=False)
    check("reject returns learned", resp.get("status") == "denied", str(resp))
    r4 = read("n3")
    check("rejected action now BLOCK", r4.verdict == "BLOCK", f"{r4.verdict}: {r4.reason}")


def test_cross_turn():
    """Item 8: feedback-loop rules SURVIVE across turns; LLM intent rules reset."""
    import os
    import time as _time
    import requests
    from adapters.sdk import ICBGuardClient
    from attestation.signer import Signer
    from gateway.api_schema import IntentProfile, PolicyRule, RulePredicate
    from gateway.config import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

    gateway = os.environ.get("ICB_GATEWAY_URL", "http://127.0.0.1:8099")
    client = ICBGuardClient(gateway)
    try:
        client.health()
    except Exception:
        print("[skip cross-turn] gateway unreachable")
        return

    signer = Signer(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    cert = client.register_tool("ct_agent", {
        "actions": ["notes"], "network": "denied", "credential": "denied",
        "process": "denied", "persistence": "denied",
        "filesystem_read": [], "filesystem_write": [],
        "sensitive_params": ["payload.note_id"],
    }, implementation_hash="sha256:ct")

    def signed(nid):
        p = IntentProfile(intent_text=f"read {nid}", rules=[
            PolicyRule(tool="notes", decision="allow",
                       predicate=RulePredicate(op="eq", field="payload.note_id", value=nid))])
        pl = p.model_dump(exclude={"signature"})
        p.signature = signer.sign(pl)
        return p

    session = f"ct-{int(_time.time()*1000)}"

    def anchor(prompt):
        requests.post(f"{gateway}/anchor_intent",
                      json={"session_id": session, "prompt": prompt}, timeout=30).raise_for_status()

    def read(nid, profile):
        return client.authorize("ct_agent", "notes", "read", profile.intent_text,
                                capability_cert_id=cert, intent_profile=profile.model_dump(),
                                payload={"note_id": nid}, session_id=session)

    print("\n[gateway: item-8 cross-turn rule survival]")
    # Turn 1: seed via the signed profile (no explicit anchor needed), approve n2
    p1 = signed("n1")
    r = read("n2", p1)
    check("turn1 outside -> CONFIRM", r.verdict == "CONFIRM", r.verdict)
    resp = client.confirm(r.confirm_token, approve=True)
    check("turn1 approve", resp.get("status") == "approved", str(resp))

    # Turn 2: re-anchor (new prompt) -> feedback rule for n2 must survive
    anchor("read note n3")  # different task
    p2 = signed("n3")
    r2 = read("n2", p2)
    check("turn2 same action -> ALLOW (feedback rule survived)", r2.verdict == "ALLOW",
          f"{r2.verdict}: {r2.reason}")
    r3 = read("n4", p2)
    check("turn2 new note -> CONFIRM (intent rules reset)", r3.verdict == "CONFIRM", r3.verdict)


def main():
    test_normalize()
    test_generalized_rule()
    if "--gateway" in sys.argv:
        test_gateway()
        test_cross_turn()
    print(f"\n{'=' * 60}\nRESULT: {_PASS} passed, {_FAIL} failed\n{'=' * 60}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
