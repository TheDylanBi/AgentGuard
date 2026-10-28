"""Lightweight two-level taint (P5), structured (P2-1).

Level 1 (deterministic): a sink action whose field value EXACTLY (or
path-boundary) references a previously-read high-risk OBJECT ID -> BLOCK.
Level 2 (derived / TAINT_UNKNOWN): after any high-risk read, a sink whose
content is NOT a direct reference but MAY be derived (LLM summary, OCR,
parse) -> CONFIRM.

P2-1 improvements over the substring version:
  - object-ID matching (exact / path-boundary), NOT substring: ``/tmp/a`` no
    longer falsely matches ``/tmp/abc``;
  - field-level tracking: nested object values and array elements are checked;
  - taint objects are structured (``{object_id, source}``).
"""
from typing import Any, Dict, List, Optional
import json
import re
import math

from .symbolic import canonicalize

HIGH_RISK_SOURCES = {
    "credential", "private_file", "PII", "financial",
    "authentication", "external_untrusted",
}

MAX_SCAN_DEPTH = 64
MAX_SCAN_NODES = 10000


class TaintScanError(ValueError):
    """A complete bounded scan could not be performed."""


def _string_fields(action):
    """Yield unambiguous paths and strings in JSON values, without decoding text.

    Cycles, unsupported objects and excessive nesting/size fail closed at the
    classification boundary. Shared but acyclic containers remain supported.
    Object keys are field names, not references; only their values are scanned.
    """
    active = set()
    nodes = 0

    def walk(value, path, depth):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_SCAN_NODES or depth > MAX_SCAN_DEPTH:
            raise TaintScanError("Taint scan resource limit exceeded")
        if isinstance(value, str):
            yield path, value
        elif isinstance(value, (dict, list)):
            identity = id(value)
            if identity in active:
                raise TaintScanError("Cyclic taint payload")
            active.add(identity)
            try:
                if isinstance(value, dict):
                    for key, child in value.items():
                        if not isinstance(key, str):
                            raise TaintScanError("Non-JSON object key")
                        suffix = "." + key if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) else "[" + json.dumps(key, ensure_ascii=False) + "]"
                        yield from walk(child, path + suffix, depth + 1)
                else:
                    for index, child in enumerate(value):
                        yield from walk(child, f"{path}[{index}]", depth + 1)
            finally:
                active.remove(identity)
        elif type(value) is float and not math.isfinite(value):
            raise TaintScanError("Non-finite JSON number")
        elif value is not None and type(value) not in (int, float, bool):
            raise TaintScanError("Unsupported taint payload value")

    yield from walk(getattr(action, "target", ""), "target", 0)
    yield from walk(getattr(action, "payload", {}) or {}, "payload", 0)


def is_source(capability: Optional[Dict]) -> bool:
    """A source READS high-risk data (declared in the capability envelope)."""
    caps = capability or {}
    return bool(caps.get("sources")) or caps.get("credential_access") == "allowed" or caps.get("credential") == "allowed"


def is_sink(capability: Optional[Dict]) -> bool:
    """A sink lets data LEAVE the security domain (effect-based)."""
    caps = capability or {}
    if caps.get("network_egress") == "allowed" or caps.get("external_share") == "allowed":
        return True
    if caps.get('financial_transfer')=='allowed':
        return True
    return caps.get("network") == "allowed" or caps.get("persistence") == "allowed"


def _oid(obj) -> str:
    """Normalize a taint object (dict or legacy str) to its canonical id."""
    value = obj.get("object_id") if isinstance(obj, dict) else obj
    return canonicalize(value) if isinstance(value, str) else ""


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


def references_tainted_field_level(action, tainted_objects, *, reference_fields=()) -> List:
    """Return ``[(field, object_id)]`` hits — field-level, object-ID based."""
    hits: List = []
    candidates = list(_string_fields(action))
    for obj in (tainted_objects or []):
        oid = _oid(obj)
        if not oid:
            continue
        for field, value in candidates:
            if field in reference_fields:
                continue  # Trusted host verified an identity reference, not content disclosure.
            if isinstance(value, str) and value and _object_matches(value, oid):
                hits.append((field, obj.get("object_id") if isinstance(obj, dict) else obj))
                break
    return hits


def references_tainted(action, tainted_objects, *, reference_fields=()) -> str:
    """Return the first matching tainted object id, or ''."""
    hits = references_tainted_field_level(action, tainted_objects, reference_fields=reference_fields)
    return hits[0][1] if hits else ""


def classify(action, capability, taint_state, *, reference_fields=(), flow_fields=()) -> Optional[tuple]:
    """For a SINK action, return (verdict, reason); None if not a sink/clean."""
    if not is_sink(capability):
        return None
    st = taint_state or {}
    if not st.get("dirty") and not st.get("tainted_objects"):
        return None
    try:
        # flow_fields are host-verified resource positions admitted to a separate
        # per-call disclosure review. They are not mere identity references.
        hit = references_tainted(action, st.get("tainted_objects", []),
                                 reference_fields=set(reference_fields)|set(flow_fields))
    except TaintScanError:
        return ("BLOCK", "Taint payload could not be fully inspected within supported JSON limits")
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
