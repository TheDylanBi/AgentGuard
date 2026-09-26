"""Behavior Alignment check (Behavior Alignment layer, P6).

Deterministic check that the ACTUAL effect is a subset of the EXPECTED effect:

    actual_behavior ⊆ expected_behavior

Violation types:
  - tool_mismatch           : the action's tool differs from the expected tool
  - target_out_of_scope     : the target is not in allowed_targets
  - recipient_out_of_scope  : a recipient is not in allowed_recipients
  - data_scope_violation    : a data source is not in allowed_data_types
  - quantity_exceeded       : more recipients/items than max_items
  - forbidden_effect:<e>    : the action produces a forbidden effect

This layer runs BEFORE the P0-P5 engine; a violation is a hard BLOCK. No LLM.
"""
from typing import Dict, List, Optional

from .effect_model import ActualEffect, ExpectedEffect
from .symbolic import canonicalize

# Effects whose danger is SEMANTIC (depends on content) and therefore handled
# by P0-P5's deterministic command-danger / symbolic layers — NOT by the
# behavior-alignment forbidden_effect check. A coarse "forbid process execution"
# would false-positive on benign shell commands (cat/head/date).
_SEMANTIC_EFFECTS = {"arbitrary_process_execution"}

# target_type values whose target is a MEANINGFUL scope subject (a plain url or
# path). JSON dumps and commands are not scope targets and are skipped.
_SCOPE_TARGET_TYPES = {"url", "path"}


def _is_json_dump(s: str) -> bool:
    s = s.strip()
    return s.startswith("{") or s.startswith("[")


def check_behavior_alignment(expected: ExpectedEffect, actual: ActualEffect,
                             capability: Optional[Dict] = None,
                             taint_state: Optional[Dict] = None) -> Dict:
    violations: List[str] = []
    caps = capability or {}

    # 1. tool constraint
    if expected.tool and expected.tool != actual.tool:
        violations.append("tool_mismatch")

    # 2. target constraint (Bug A fix): only for plain url/path targets. JSON
    #    dumps (target == json.dumps(payload)) and shell commands are NOT scope
    #    targets, so this check no longer fires on them.
    target_type = caps.get("target_type")
    if (expected.allowed_targets
            and target_type in _SCOPE_TARGET_TYPES
            and not _is_json_dump(actual.target)):
        canon_target = canonicalize(actual.target)
        if canon_target not in {canonicalize(x) for x in expected.allowed_targets}:
            violations.append("target_out_of_scope")

    # 3. recipient constraint
    if expected.allowed_recipients:
        allowed = {canonicalize(x) for x in expected.allowed_recipients}
        actual_recipients = {canonicalize(x) for x in actual.recipients}
        if actual_recipients and not actual_recipients.issubset(allowed):
            violations.append("recipient_out_of_scope")

    # 4. data constraint
    if expected.allowed_data_types:
        allowed = {x for x in expected.allowed_data_types}
        actual_data = {x for x in actual.data_sources}
        if actual_data and not actual_data.issubset(allowed):
            violations.append("data_scope_violation")

    # 5. quantity constraint
    if expected.max_items is not None:
        if len(actual.recipients) > expected.max_items:
            violations.append("quantity_exceeded")

    # 6. forbidden effects (Bug B fix): skip semantic effects like
    #    arbitrary_process_execution (shell danger is judged by command-danger).
    for effect in actual.side_effects:
        if effect in expected.forbidden_effects and effect not in _SEMANTIC_EFFECTS:
            violations.append(f"forbidden_effect:{effect}")

    return {"aligned": len(violations) == 0, "violations": violations}
