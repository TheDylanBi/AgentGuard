"""P4 tests: evidence-certificate verification + TOCTOU binding.

Unit-level (no gateway): exercises the engine's trust root directly.

    python tests/test_certificate.py
"""
import sys
import time as _time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from policy.engine import PolicyEngine
from attestation.signer import Signer
from gateway.config import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

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


def test_signer_verify():
    signer = Signer(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    payload = {"a": 1, "b": "x", "nested": {"c": [1, 2, 3]}}
    sig = signer.sign(payload)
    check("signer.verify valid", signer.verify(payload, sig) is True)
    check("signer.verify tampered", signer.verify({"a": 1, "b": "x", "nested": {"c": [1, 2, 4]}}, sig) is False)
    check("signer.verify bad prefix", signer.verify(payload, "deadbeef") is False)


def test_certificate():
    signer = Signer(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    eng = PolicyEngine(str(ROOT / "policy" / "policies"))

    def make_cert(trust, action_type, action_target, expires=None, sig_ok=True):
        payload = {
            "predicate": f"UI_ELEMENT(target={action_target!r})",
            "trust": trust,
            "sources": [{"type": "a11y_tree", "verifier": "a11y-tree-1.0.0", "confidence": 0.99}],
        }
        sig = signer.sign(payload) if sig_ok else "ed25519:AAAA"
        return {
            "predicate": payload["predicate"],
            "trust": trust,
            "sources": payload["sources"],
            "signature": sig,
            "payload": payload,
            "action_type": action_type,
            "action_target": action_target,
            "expires_at": expires if expires is not None else int(_time.time()) + 300,
        }

    def verifier(c):
        payload = c.get("payload")
        sig = c.get("signature")
        if payload is None or sig is None:
            return False, "missing payload/signature"
        if not signer.verify(payload, sig):
            return False, "bad signature"
        return True, "ok"

    caps = {"actions": ["click"], "network": "denied", "credential": "denied",
            "process": "denied", "persistence": "denied"}
    action = SimpleNamespace(type="click", target="Log In", payload={})

    print("\n[P4 certificate verification]")
    # 1. valid cert (trusted) -> engine uses verified trust -> ALLOW
    r = eng.evaluate(action, "untrusted", 0, capability=caps,
                     certificate=make_cert("trusted", "click", "Log In"),
                     certificate_verifier=verifier)
    check("verified trusted -> ALLOW", r["verdict"] == "ALLOW", str(r))

    # 2. cert says untrusted, caller lies trusted -> engine uses cert -> CONFIRM
    r = eng.evaluate(action, "trusted", 0, capability=caps,
                     certificate=make_cert("untrusted", "click", "Log In"),
                     certificate_verifier=verifier)
    check("cert trust overrides caller trust -> CONFIRM", r["verdict"] == "CONFIRM", str(r))

    # 3. binding mismatch (cert proves a different target) -> BLOCK
    action2 = SimpleNamespace(type="click", target="Upload SSH key", payload={})
    r = eng.evaluate(action2, "trusted", 0, capability=caps,
                     certificate=make_cert("trusted", "click", "Log In"),
                     certificate_verifier=verifier)
    check("binding mismatch -> BLOCK", r["verdict"] == "BLOCK", str(r))

    # 4. expired -> BLOCK
    r = eng.evaluate(action, "trusted", 0, capability=caps,
                     certificate=make_cert("trusted", "click", "Log In", expires=int(_time.time()) - 1),
                     certificate_verifier=verifier)
    check("expired -> BLOCK", r["verdict"] == "BLOCK", str(r))

    # 5. bad signature -> BLOCK
    r = eng.evaluate(action, "trusted", 0, capability=caps,
                     certificate=make_cert("trusted", "click", "Log In", sig_ok=False),
                     certificate_verifier=verifier)
    check("bad signature -> BLOCK", r["verdict"] == "BLOCK", str(r))

    # 6. invalid trust value -> BLOCK
    r = eng.evaluate(action, "trusted", 0, capability=caps,
                     certificate=make_cert("totally_trusted", "click", "Log In"),
                     certificate_verifier=verifier)
    check("invalid trust value -> BLOCK", r["verdict"] == "BLOCK", str(r))

    # 7. no certificate -> fall back to caller trust (backward compat)
    r = eng.evaluate(action, "trusted", 0, capability=caps)
    check("no cert -> caller trust (backward compat)", r["verdict"] == "ALLOW", str(r))


def main():
    test_signer_verify()
    test_certificate()
    print(f"\n{'=' * 60}\nRESULT: {_PASS} passed, {_FAIL} failed\n{'=' * 60}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
