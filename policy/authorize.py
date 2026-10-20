"""Unified action authorization: Hard engine boundaries + Behavior Alignment (P6).

The single decision function shared by the offline replay and (in principle)
the live gateway.

Responsibilities (change 4 — strict separation):
  - Intent     (trusted user prompt)   -> what the user WANTS to do
  - Capability (operator-declared)     -> what the tool can AT MOST do
  - P6  Behavior Alignment             -> does THIS actual action exceed the
                                          user's expected effect? (BLOCK)
  - P0-P5 Policy Engine                -> capability / symbolic / sink /
                                          sensitive / taint / certificate

A behavior misalignment is a hard BLOCK (the actual effect is NOT a subset of
of the expected effect). No LLM judges individual actions.
"""
from typing import Any, Dict, Optional

from .effect_model import build_expected_effect
from .behavior import extract_actual_effect
from .behavior_alignment import check_behavior_alignment


def authorize_action(action, *, capability: Optional[Dict], engine,
                     rules: Optional[list] = None,
                     effect_profile: Optional[Dict] = None,
                     taint_state: Optional[Dict] = None,
                     trust: str = "unknown", evidence_count: int = 0,
                     intent_text: str = "",
                     intent_profile: Optional[Dict] = None,
                     certificate=None, certificate_verifier=None,
                     llm_danger=None, llm_reason=None,
                     enable_rules: bool = True,
                     require_capability: bool = True, resolved_recipients=None) -> Dict:
    """Decide BLOCK/CONFIRM/ALLOW for one tool call.

    Returns the same dict shape as ``PolicyEngine.evaluate`` so callers can
    reuse the metrics pipeline unchanged.
    """
    # P0-P5 deterministic policy engine.
    decision = engine.evaluate(
        action, trust, evidence_count, intent_text,
        capability=capability, rules=rules, taint_state=taint_state,
        intent_profile=intent_profile, certificate=certificate,
        certificate_verifier=certificate_verifier,
        llm_danger=llm_danger, llm_reason=llm_reason,
        enable_rules=enable_rules, require_capability=require_capability,
    )

    if decision["verdict"] == "BLOCK":
        return decision
    # Behavior misalignment is a hard denial even when the engine requests approval.
    # Only fires when the tool has a static effect schema and an intent-effect
    # profile is available; otherwise it degrades to the engine alone.
    if effect_profile is not None and (capability or {}).get("effect_type"):
        expected = build_expected_effect(effect_profile, capability, action.type)
        actual = extract_actual_effect(
            action.type, action.target,
            getattr(action, "payload", None) or {}, capability, taint_state,
            resolved_recipients=resolved_recipients,
        )
        alignment = check_behavior_alignment(expected, actual, capability, taint_state)
        if not alignment["aligned"]:
            # Change 1: a behavior misalignment is a HARD BLOCK — the actual
            # effect is not a subset of the expected effect. It is NOT a request
            # to expand privileges, so NO auto policy_update is attached
            # (change 2): privilege expansion goes through a separate flow.
            return {
                "verdict": "BLOCK",
                "reason": "行为超出预期效应：" + ",".join(alignment["violations"]),
                "rule": "behavior_alignment",
            }

    if ((capability or {}).get("effect_type") and effect_profile is None
            and decision["verdict"] == "ALLOW"):
        return {"verdict": "CONFIRM", "reason": "Expected effects unavailable; explicit approval required",
                "rule": "behavior_alignment.unavailable"}
    return decision
