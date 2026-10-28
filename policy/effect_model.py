"""Expected / Actual Effect model (Behavior Alignment layer, P6).

The core idea: an intent must describe what EFFECTS are allowed (recipients,
data types, operations), not merely which tool names may be called. A tool
call is safe only when its ACTUAL effect is a subset of the EXPECTED effect:

    actual_behavior  ⊆  expected_behavior

This module is pure data structures + a deterministic builder; the LLM only
produces the intent profile (``policy.intent_anchor.anchor_effect_llm``), never
judges individual actions.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ExpectedEffect:
    tool: str
    operation: Optional[str] = None
    allowed_targets: List[str] = field(default_factory=list)
    allowed_recipients: List[str] = field(default_factory=list)
    allowed_data_types: List[str] = field(default_factory=list)
    max_items: Optional[int] = None
    allowed_params: Dict[str, Any] = field(default_factory=dict)
    forbidden_effects: List[str] = field(default_factory=list)


@dataclass
class ActualEffect:
    tool: str
    target: str
    payload: Dict[str, Any] = field(default_factory=dict)
    data_sources: List[str] = field(default_factory=list)
    recipients: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    # change 5: True when the effect could NOT be determined (no effect schema
    # and no recipients extracted). Sensitive/sink ops with unknown effect must
    # NOT default to "no violation".
    unknown: bool = False
    # Resource IDs are not addresses. A host resolver must supply recipients
    # for effects that notify subjects hidden behind an object reference.
    recipients_known: bool = True


# effect_type -> the capability flag that authorizes it. If the flag is NOT
# "allowed", the effect is ALWAYS forbidden (a poisoned LLM cannot remove it).
_EFFECT_CAP_FLAG = {
    "credential_access": "credential_access",
    "network_navigation": "network_egress",
    "external_communication": "external_share",
    "financial_transfer": "financial_transfer",
    "share": "external_share",
    "physical_action": "external_share",
    "arbitrary_process_execution": "process",
}


def _capability_forbidden_effects(capability: Optional[Dict]) -> set:
    """Effects the CAPABILITY hard-denies (operator-declared, trusted).

    These are ALWAYS forbidden in the Expected effect, so a poisoned / wrong
    intent LLM cannot EXPAND the expected effect beyond the capability
    (change 3: ``Expected ⊆ Capability``).
    """
    caps = capability or {}
    forbidden = set()
    for effect, flag in _EFFECT_CAP_FLAG.items():
        if caps.get(flag, "denied") != "allowed":
            forbidden.add(effect)
    return forbidden


def build_expected_effect(intent_profile: Optional[Dict], capability: Optional[Dict],
                          tool: str) -> ExpectedEffect:
    """Derive the ExpectedEffect for a tool from the (trajectory-free) intent
    profile, CONSTRAINED by the capability (change 3).

    ``forbidden_effects`` = LLM's forbidden effects ∪ capability-denied effects.
    The capability part is hard/trusted; the LLM part can only RESTRICT further,
    never EXPAND the expected effect.
    """
    ip = intent_profile or {}
    forbidden = set(str(x) for x in (ip.get("forbidden_effects") or []))
    forbidden |= _capability_forbidden_effects(capability)
    return ExpectedEffect(
        tool=tool,
        allowed_targets=[str(x) for x in (ip.get("allowed_targets") or [])],
        allowed_recipients=[str(x) for x in (ip.get("allowed_recipients") or [])],
        allowed_data_types=[str(x) for x in (ip.get("allowed_data_types") or [])],
        max_items=ip.get("max_items") if isinstance(ip.get("max_items"), int) else None,
        forbidden_effects=list(forbidden),
    )
