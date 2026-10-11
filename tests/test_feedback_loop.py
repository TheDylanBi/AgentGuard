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
    import unittest
    from test_security_hardening import SecurityHardeningTests
    suite = unittest.TestSuite(SecurityHardeningTests(name) for name in [
        "test_approval_is_exact_and_single_action", "test_cross_turn_feedback_not_preserved",
        "test_budget_never_auto_allows_shell"])
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        raise AssertionError("Approval contract failed")


def main():
    test_normalize()
    test_generalized_rule()
    if "--gateway" in sys.argv:
        test_gateway()

    print(f"\n{'=' * 60}\nRESULT: {_PASS} passed, {_FAIL} failed\n{'=' * 60}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
