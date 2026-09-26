"""Tests for the Behavior Alignment layer (P6).

    python tests/test_behavior_alignment.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from policy.effect_model import build_expected_effect, ExpectedEffect
from policy.behavior import extract_actual_effect
from policy.behavior_alignment import check_behavior_alignment

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


def test_extract():
    print("\n[extract_actual_effect]")
    caps = {"effect_type": "external_communication", "target_type": "recipient",
            "sources": ["PII"]}
    a = extract_actual_effect("gmail_send_email", "send",
                              {"to": "attacker@evil.com", "subject": "hi"}, caps)
    check("extracts recipient", "attacker@evil.com" in a.recipients, str(a.recipients))
    check("extracts side_effect", "external_communication" in a.side_effects, str(a.side_effects))
    check("extracts data_sources", "PII" in a.data_sources, str(a.data_sources))

    caps2 = {"effect_type": "filesystem_read", "target_type": "path", "sources": ["private_file"]}
    a2 = extract_actual_effect("read_file", "/etc/passwd", {}, caps2)
    check("path fallback to target", a2.recipients == ["/etc/passwd"], str(a2.recipients))


def test_alignment():
    print("\n[check_behavior_alignment]")
    caps = {"effect_type": "external_communication", "target_type": "recipient",
            "sources": ["PII"]}

    intent = {
        "allowed_recipients": ["alice@company.com"],
        "allowed_targets": [],
        "allowed_data_types": ["PII"],
        "max_items": 1,
        "forbidden_effects": ["financial_transfer"],
    }

    def align(to):
        expected = build_expected_effect(intent, caps, "gmail_send_email")
        actual = extract_actual_effect("gmail_send_email", "send", {"to": to}, caps)
        return check_behavior_alignment(expected, actual, caps)

    r = align("alice@company.com")
    check("aligned", r["aligned"] is True and r["violations"] == [], str(r))

    r = align("attacker@evil.com")
    check("recipient_out_of_scope", r["aligned"] is False and "recipient_out_of_scope" in r["violations"], str(r))

    # data scope: intent forbids touching this data type
    intent2 = dict(intent, allowed_data_types=["contact"])
    expected = build_expected_effect(intent2, caps, "gmail_send_email")
    actual = extract_actual_effect("gmail_send_email", "send", {"to": "alice@company.com"}, caps)
    r = check_behavior_alignment(expected, actual, caps)
    check("data_scope_violation", "data_scope_violation" in r["violations"], str(r))

    # quantity
    intent3 = dict(intent, max_items=1)
    expected = build_expected_effect(intent3, caps, "gmail_send_email")
    actual = extract_actual_effect("gmail_send_email", "send",
                                   {"to": ["alice@company.com", "bob@company.com"]}, caps)
    r = check_behavior_alignment(expected, actual, caps)
    check("quantity_exceeded", "quantity_exceeded" in r["violations"], str(r))

    # forbidden effect
    caps4 = {"effect_type": "financial_transfer", "target_type": "recipient", "sources": ["financial"]}
    expected = build_expected_effect(intent, caps4, "bank_manager_pay_bill")
    actual = extract_actual_effect("bank_manager_pay_bill", "pay",
                                   {"payee_id": "P-123", "amount": 100}, caps4)
    r = check_behavior_alignment(expected, actual, caps4)
    check("forbidden_effect:financial_transfer",
          "forbidden_effect:financial_transfer" in r["violations"], str(r))

    # target out of scope
    caps5 = {"effect_type": "network_navigation", "target_type": "url", "sources": []}
    intent5 = {"allowed_targets": ["https://internal.example.com"], "forbidden_effects": []}
    expected = build_expected_effect(intent5, caps5, "web_browser_navigate_to")
    actual = extract_actual_effect("web_browser_navigate_to", "https://evil.com", {}, caps5)
    r = check_behavior_alignment(expected, actual, caps5)
    check("target_out_of_scope", "target_out_of_scope" in r["violations"], str(r))


def main():
    test_extract()
    test_alignment()
    print(f"\n{'=' * 60}\nRESULT: {_PASS} passed, {_FAIL} failed\n{'=' * 60}")
    sys.exit(1 if _FAIL else 0)


if __name__ == "__main__":
    main()
