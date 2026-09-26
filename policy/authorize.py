"""Unified action authorization: Behavior Alignment (P6) -> P0-P5 engine.

The single decision function shared by the offline replay and (in principle)
the live gateway:

    Expected Effect  vs  Actual Effect   (Behavior Alignment, P6)
              ↓
    P0-P5 Policy Engine                 (capability / symbolic / semantic / taint)

A behavior misalignment is a hard BLOCK BEFORE the engine runs. The engine
then applies the deterministic P0-P5 checks. No LLM judges individual actions.
"""
from typing import Any, Dict, Optional

from .effect_model import build_expected_effect
from .behavior import extract_actual_effect
from .behavior_alignment import check_behavior_alignment
from . import symbolic


def authorize_action(action, *, capability: Optional[Dict], engine,
                     rules: Optional[list] = None,
                     effect_profile: Optional[Dict] = None,
                     taint_state: Optional[Dict] = None,
                     trust: str = "unknown", evidence_count: int = 0,
                     intent_text: str = "",
                     intent_profile: Optional[Dict] = None,
                     certificate=None, certificate_verifier=None,
                     consistency=None, consistency_reason=None,
                     llm_danger=None, llm_reason=None, roles=None,
                     enable_rules: bool = True,
                     require_capability: bool = True) -> Dict:
    """Decide BLOCK/CONFIRM/ALLOW for one tool call.

    Returns the same dict shape as ``PolicyEngine.evaluate`` so callers can
    reuse the metrics pipeline unchanged.
    """
    # P6: Behavior Alignment (runs BEFORE the P0-P5 engine).
    # Only fires when the tool has a static effect schema and an intent-effect
    # profile is available; otherwise it degrades to the engine alone.
    if effect_profile is not None and (capability or {}).get("effect_type"):
        expected = build_expected_effect(effect_profile, capability, action.type)
        actual = extract_actual_effect(
            action.type, action.target,
            getattr(action, "payload", None) or {}, capability, taint_state,
        )
        alignment = check_behavior_alignment(expected, actual, capability, taint_state)
        if not alignment["aligned"]:
            # P0: LLM-inferred semantic constraints are UNCERTAIN -> CONFIRM,
            # never BLOCK. Item-7 feedback loop: attach a GENERALIZED allow rule
            # (sensitive pinned, non-sensitive relaxed) for approval.
            fields = symbolic.action_fields(
                action.type, action.target, getattr(action, "payload", None) or {}
            )
            sensitive = symbolic.normalize_sensitive_fields(
                (capability or {}).get("sensitive_params") or []
            )
            update_rule = symbolic.make_generalized_rule(
                action.type, fields, sensitive_fields=sensitive, decision="allow"
            )
            return {
                "verdict": "CONFIRM",
                "reason": "行为超出预期效应（语义推断）：" + ",".join(alignment["violations"]),
                "rule": "behavior_alignment",
                "policy_update": {
                    "rule": update_rule,
                    "classification": "expansion",
                    "request_id": "",
                },
            }

    # P0-P5 deterministic policy engine.
    return engine.evaluate(
        action, trust, evidence_count, intent_text,
        capability=capability, rules=rules, taint_state=taint_state,
        intent_profile=intent_profile, certificate=certificate,
        certificate_verifier=certificate_verifier, consistency=consistency,
        consistency_reason=consistency_reason, llm_danger=llm_danger,
        llm_reason=llm_reason, roles=roles, enable_rules=enable_rules,
        require_capability=require_capability,
    )
