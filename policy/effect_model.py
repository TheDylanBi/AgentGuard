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


def build_expected_effect(intent_profile: Optional[Dict], capability: Optional[Dict],
                          tool: str) -> ExpectedEffect:
    """Derive the ExpectedEffect for a tool from the (trajectory-free) intent
    profile. The intent profile is global per task; the capability only carries
    the tool's static effect schema (effect_type/target_type)."""
    ip = intent_profile or {}
    return ExpectedEffect(
        tool=tool,
        allowed_targets=[str(x) for x in (ip.get("allowed_targets") or [])],
        allowed_recipients=[str(x) for x in (ip.get("allowed_recipients") or [])],
        allowed_data_types=[str(x) for x in (ip.get("allowed_data_types") or [])],
        max_items=ip.get("max_items") if isinstance(ip.get("max_items"), int) else None,
        forbidden_effects=[str(x) for x in (ip.get("forbidden_effects") or [])],
    )
