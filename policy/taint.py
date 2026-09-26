"""Lightweight two-level taint (P5), structured (P2-1).

Level 1 (deterministic): a sink action whose field value EXACTLY (or
path-boundary) references a previously-read high-risk OBJECT ID -> BLOCK.
Level 2 (derived / TAINT_UNKNOWN): after any high-risk read, a sink whose
content is NOT a direct reference but MAY be derived (LLM summary, OCR,
parse) -> CONFIRM.

P2-1 improvements over the substring version:
  - object-ID matching (exact / path-boundary), NOT substring: ``/tmp/a`` no
    longer falsely matches ``/tmp/abc``;
  - field-level tracking: each payload field is checked separately;
  - taint objects are structured (``{object_id, source}``).
"""
from typing import Any, Dict, List, Optional

from .symbolic import canonicalize

HIGH_RISK_SOURCES = {
    "credential", "private_file", "PII", "financial",
    "authentication", "external_untrusted",
}


def is_source(capability: Optional[Dict]) -> bool:
    """A source READS high-risk data (declared in the capability envelope)."""
    return bool((capability or {}).get("sources"))


def is_sink(capability: Optional[Dict]) -> bool:
    """A sink lets data LEAVE the security domain (effect-based)."""
    caps = capability or {}
    if "network_egress" in caps or "external_share" in caps:
        return caps.get("network_egress") == "allowed" or caps.get("external_share") == "allowed"
    return caps.get("network") == "allowed" or caps.get("persistence") == "allowed"


def _oid(obj) -> str:
    """Normalize a taint object (dict or legacy str) to its canonical id."""
    return canonicalize(obj.get("object_id") if isinstance(obj, dict) else obj)


def _object_matches(field_value: str, object_id: str) -> bool:
    """Exact or path-boundary match (NOT substring).

    ``/tmp/a`` matches ``/tmp/a`` and ``/tmp/a/x``, but NOT ``/tmp/abc``.
    """
    fv = canonicalize(field_value)
    oid = canonicalize(object_id)
    if not fv or not oid:
        return False
    if fv == oid:
        return True
    if "/" in oid or "\\" in oid:
        return fv.startswith(oid + "/") or fv.startswith(oid + "\\")
    return False


def references_tainted_field_level(action, tainted_objects) -> List:
    """Return ``[(field, object_id)]`` hits — field-level, object-ID based."""
    hits: List = []
    payload = getattr(action, "payload", None) or {}
    candidates = [("target", canonicalize(getattr(action, "target", "")))]
    candidates += [(f"payload.{k}", canonicalize(v)) for k, v in payload.items()]
    for obj in (tainted_objects or []):
        oid = _oid(obj)
        if not oid:
            continue
        for field, value in candidates:
            if isinstance(value, str) and value and _object_matches(value, oid):
                hits.append((field, obj.get("object_id") if isinstance(obj, dict) else obj))
                break
    return hits


def references_tainted(action, tainted_objects) -> str:
    """Return the first matching tainted object id, or ''."""
    hits = references_tainted_field_level(action, tainted_objects)
    return hits[0][1] if hits else ""


def classify(action, capability, taint_state) -> Optional[tuple]:
    """For a SINK action, return (verdict, reason); None if not a sink/clean."""
    if not is_sink(capability):
        return None
    st = taint_state or {}
    hit = references_tainted(action, st.get("tainted_objects", []))
    if hit:
        return ("BLOCK",
                f"确定性 taint：动作直接引用了已读的高风险来源对象 '{hit}'")
    if st.get("dirty"):
        return ("CONFIRM",
                "派生 taint（TAINT_UNKNOWN）：会话已接触高风险数据，"
                "此 sink 内容可能派生自它（LLM 摘要/OCR/解析），需人工确认")
    return None


def record_source_read(taint_state: Dict, object_id: Any, source=None) -> Dict:
    """Record a high-risk read as a STRUCTURED object (id + source)."""
    st = taint_state or {"tainted_objects": [], "dirty": False}
    objs = list(st.get("tainted_objects", []))
    oid = _oid(object_id)
    if oid and oid not in [_oid(o) for o in objs]:
        objs.append({
            "object_id": str(object_id),
            "source": str(source) if source else "",
        })
    st["tainted_objects"] = objs
    st["dirty"] = True
    return st
