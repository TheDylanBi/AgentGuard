"""Actual Behavior extraction (Behavior Alignment layer, P6).

Maps a concrete tool call (tool, target, payload) into an ActualEffect using
the tool's STATIC capability schema (target_type tells us which payload keys
are recipients/paths/urls/commands; effect_type tells us the side effect).
This is deterministic — no LLM.
"""
from typing import Any, Dict, List, Optional

from .effect_model import ActualEffect

# payload keys that carry an "external subject" for each target_type
_TARGET_KEYS: Dict[str, List[str]] = {
    "recipient": [
        "to", "cc", "bcc", "recipient", "recipients", "destination",
        "destination_address", "payee_id", "to_address", "to_account",
        "email_address", "to_phone_numbers", "address", "account",
        "from_account_number", "service_account_number",
    ],
    "path": ["path", "filename", "item_path", "file_path", "user_cloud_file_path",
             "source_video_path", "source_audio_path"],
    "url": ["url"],
    "process": ["command"],
}


def _extract_values(payload: Optional[Dict], keys: List[str]) -> List[str]:
    out: List[str] = []
    for k in keys:
        v = (payload or {}).get(k)
        if isinstance(v, (list, tuple)):
            out.extend(str(x) for x in v if x is not None)
        elif v is not None:
            out.append(str(v))
    return out


def extract_actual_effect(tool: str, target: str, payload: Optional[Dict],
                          capability: Optional[Dict] = None,
                          taint_state: Optional[Dict] = None) -> ActualEffect:
    """Extract the ACTUAL effect of a tool call from its arguments."""
    caps = capability or {}
    target_type = caps.get("target_type")
    recipients = _extract_values(payload, _TARGET_KEYS.get(target_type or "", []))
    if not recipients and target:
        # fallback: when no explicit recipient key is present, the target itself
        # is the subject (e.g. a path, url or command).
        recipients = [str(target)]

    effect_type = caps.get("effect_type")
    side_effects = [effect_type] if effect_type else []

    return ActualEffect(
        tool=tool,
        target=str(target),
        payload=dict(payload or {}),
        data_sources=[str(s) for s in (caps.get("sources") or [])],
        recipients=recipients,
        side_effects=side_effects,
    )
