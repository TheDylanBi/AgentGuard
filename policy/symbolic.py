"""Progent-style symbolic least-privilege rules (borrowed, adapted to ICB-Guard).

Represents privilege as a set of symbolic rules over (tool, arguments)::

    {"tool": "email", "decision": "allow",
     "predicate": {"op": "eq", "field": "to", "value": "alice@company.com"}}

Every tool call is checked against the rule set deterministically:

  - a matching ``deny`` rule  -> ``"deny"``    -> BLOCK
  - a matching ``allow`` rule -> ``"allow"``   -> within least privilege
  - no matching rule          -> ``"outside"`` -> expansion -> CONFIRM

Policy updates are classified with an SMT solver (z3) as:

  - ``narrowing`` (restriction)  -> auto-applied
  - ``expansion`` (broadening)   -> requires explicit approval

The allowed action space therefore only shrinks without approval
(monotonic confinement), preventing silent privilege escalation.

This module is pure logic over plain dicts (no pydantic / fastapi), so it
can be unit-tested in isolation. The wire models live in ``gateway.api_schema``.

Predicate DSL (JSON-serializable tree)::

    {"op": "true"}
    {"op": "and"|"or", "args": [pred, ...]}
    {"op": "not", "args": [pred]}
    {"op": "eq"|"ne"|"le"|"ge", "field": "target"|"payload.<key>", "value": scalar}
    {"op": "in"|"not_in", "field": ..., "value": [ ... ]}
    {"op": "glob", "field": ..., "value": "/workspace/*"}
    {"op": "contains", "field": ..., "value": "substring"}
"""
import fnmatch
import re
import unicodedata
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

try:
    import z3
    _HAS_Z3 = True
except Exception:  # pragma: no cover - z3 is optional at runtime
    z3 = None
    _HAS_Z3 = False


# ---------------------------------------------------------------------------
# concrete predicate evaluation (no solver needed)
# ---------------------------------------------------------------------------

def _num(v) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def canonicalize(value):
    """Normalize a value for safe, SYMMETRIC comparison (Attack 1 defense).

    Applied to BOTH the action field value and the rule value so equivalent
    forms match the same way:
      - NFC Unicode normalization (é vs e+combining accent)
      - strip surrounding whitespace
      - percent-decode (%40 -> @, %2f -> /) so encoded aliases do not bypass
      - lowercase (email/domain case-insensitivity; errs toward matching, which
        is safe for deny rules: over-blocking is safer than under-blocking)

    Non-string values are returned unchanged (le/ge still compare numerically).
    """
    if not isinstance(value, str):
        return value
    s = unicodedata.normalize("NFC", value).strip()
    try:
        s = urllib.parse.unquote(s)
    except Exception:  # pragma: no cover - never break the evaluator
        pass
    return s.lower()


def _canon(value):
    return canonicalize(value)


def predicate_holds(pred: Dict[str, Any], fields: Dict[str, Any]) -> bool:
    """Evaluate a predicate against concrete action fields (canonicalized).

    ``fields`` maps ``"type"``, ``"target"`` and ``"payload.<key>"`` to values.
    Both sides of string comparisons are canonicalized so equivalent forms
    (case / percent-encoding / Unicode) match the same way.
    """
    if not isinstance(pred, dict):
        return False
    op = pred.get("op", "true")
    if op == "true":
        return True
    if op == "and":
        return all(predicate_holds(a, fields) for a in pred.get("args", []))
    if op == "or":
        return any(predicate_holds(a, fields) for a in pred.get("args", []))
    if op == "not":
        args = pred.get("args", [])
        return (not predicate_holds(args[0], fields)) if args else False

    v = fields.get(pred.get("field"))
    val = pred.get("value")
    if op == "eq":
        return _canon(v) == _canon(val)
    if op == "ne":
        return _canon(v) != _canon(val)
    if op == "le":
        nv, nval = _num(v), _num(val)
        return nv is not None and nval is not None and nv <= nval
    if op == "ge":
        nv, nval = _num(v), _num(val)
        return nv is not None and nval is not None and nv >= nval
    if op == "in":
        return isinstance(val, (list, tuple, set)) and _canon(v) in [_canon(x) for x in val]
    if op == "not_in":
        return isinstance(val, (list, tuple, set)) and _canon(v) not in [_canon(x) for x in val]
    if op == "glob":
        return isinstance(v, str) and fnmatch.fnmatch(_canon(v), _canon(val))
    if op == "contains":
        return v is not None and _canon(val) in _canon(v)
    return False


def action_fields(action_type: str, target: str,
                  payload: Optional[Dict] = None) -> Dict[str, Any]:
    """Build the concrete field map for one tool call."""
    fields: Dict[str, Any] = {"type": action_type, "target": target}
    for k, v in (payload or {}).items():
        fields[f"payload.{k}"] = v
    return fields


def check_rules(action_type: str, fields: Dict[str, Any],
                rules: List[dict]) -> Tuple[str, Optional[dict]]:
    """Deterministic least-privilege check with rule precedence.

    Returns ``("deny"|"allow"|"outside", matched_rule_or_None)``.

    Precedence (most specific wins; deny wins within the same specificity):
      1. tool-specific deny   -> BLOCK (explicit forbid always wins)
      2. tool-specific allow  -> ALLOW (specific exception overrides a
                                 wildcard ``deny *`` default-deny)
      3. wildcard deny        -> BLOCK (default deny)
      4. wildcard allow       -> ALLOW (default allow)
    """
    specific_deny = None
    specific_allow = None
    wild_deny = None
    wild_allow = None
    for r in rules or []:
        tool = r.get("tool", "*")
        if tool != "*" and tool != action_type:
            continue
        if not predicate_holds(r.get("predicate") or {}, fields):
            continue
        dec = r.get("decision")
        if dec == "deny":
            if tool == "*":
                wild_deny = wild_deny or r
            else:
                specific_deny = specific_deny or r
        elif dec == "allow":
            if tool == "*":
                wild_allow = wild_allow or r
            else:
                specific_allow = specific_allow or r
    if specific_deny is not None:
        return "deny", specific_deny
    if specific_allow is not None:
        return "allow", specific_allow
    if wild_deny is not None:
        return "deny", wild_deny
    if wild_allow is not None:
        return "allow", wild_allow
    return "outside", None


def normalize_sensitive_fields(sensitive_list) -> List[str]:
    """Normalize a sensitive_params list to predicate field names.

    Bare payload keys ("to") -> "payload.to"; "target"/"type" and "payload.*"
    are kept as-is.
    """
    out = []
    for p in (sensitive_list or []):
        p = str(p)
        if p in ("target", "type") or p.startswith("payload."):
            out.append(p)
        else:
            out.append("payload." + p)
    return out


def make_generalized_rule(action_type: str, fields: Dict[str, Any],
                          sensitive_fields=None, decision: str = "allow") -> Dict[str, Any]:
    """Feedback-loop rule with TWO-LEVEL granularity (item 7).

    - ``target`` and every SENSITIVE field are pinned to their concrete values
      (these are the security-critical subjects);
    - non-sensitive scalar fields (subject/body/content/...) are RELAXED
      (omitted), so a change in incidental detail does NOT re-trigger CONFIRM.

    ``decision`` is "allow" (approval -> expansion) or "deny" (rejection ->
    narrowing).
    """
    sensitive = set(sensitive_fields or [])
    conjuncts = []
    for f in sorted(fields):
        if f == "type":
            continue
        v = fields[f]
        if not (isinstance(v, (str, int, float)) and not isinstance(v, bool)):
            continue
        if f == "target" or f in sensitive:
            conjuncts.append({"op": "eq", "field": f, "value": v})
        # non-sensitive fields are relaxed (omitted from the predicate)
    if not conjuncts:
        conjuncts = [{"op": "eq", "field": "target", "value": fields.get("target", "")}]
    pred = conjuncts[0] if len(conjuncts) == 1 else {"op": "and", "args": conjuncts}
    reason = (
        "feedback loop: approved expansion (sensitive pinned, non-sensitive relaxed)"
        if decision == "allow"
        else "feedback loop: rejected -> narrowing deny"
    )
    return {"tool": action_type, "decision": decision, "predicate": pred, "reason": reason}


def make_minimal_allow_rule(action_type: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Smallest allow-rule that covers exactly this concrete action.

    Pins ``target`` and every scalar payload field to its concrete value, so
    approving an expansion grants no more than this exact call.
    """
    conjuncts = []
    for f in sorted(fields):
        if f == "type":
            continue  # the rule's ``tool`` already scopes the action type
        v = fields[f]
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            conjuncts.append({"op": "eq", "field": f, "value": v})
    if not conjuncts:
        pred: Dict[str, Any] = {"op": "true"}
    elif len(conjuncts) == 1:
        pred = conjuncts[0]
    else:
        pred = {"op": "and", "args": conjuncts}
    return {
        "tool": action_type,
        "decision": "allow",
        "predicate": pred,
        "reason": "runtime expansion (minimal rule pinned to concrete arguments)",
    }


# ---------------------------------------------------------------------------
# SMT encoding for monotonic update classification
# ---------------------------------------------------------------------------

_VAR_SAFE = re.compile(r"[^0-9a-zA-Z_]")


def _collect_field_types(preds: List[dict]) -> Dict[str, str]:
    """Infer per-field z3 types from the values appearing in predicates.

    A field is ``int`` / ``str`` only when *all* its sample values share that
    kind; anything else becomes ``mixed`` (unencodable -> conservative).
    """
    kinds: Dict[str, set] = {}

    def walk(p: dict):
        op = p.get("op", "true")
        if op in ("and", "or", "not"):
            for a in p.get("args", []):
                if isinstance(a, dict):
                    walk(a)
            return
        f = p.get("field")
        if not f:
            return
        v = p.get("value")
        vals = list(v) if isinstance(v, (list, tuple)) else [v]
        for x in vals:
            if isinstance(x, bool):
                k = "bool"
            elif isinstance(x, (int, float)):
                k = "int"
            elif isinstance(x, str):
                k = "str"
            else:
                continue
            kinds.setdefault(f, set()).add(k)

    for p in preds:
        if isinstance(p, dict):
            walk(p)

    types: Dict[str, str] = {}
    for f, ks in kinds.items():
        ks.discard("bool")
        if ks == {"int"}:
            types[f] = "int"
        elif ks == {"str"}:
            types[f] = "str"
        else:
            types[f] = "mixed"
    return types


def _to_z3(pred: dict, vars_: Dict[str, Any], types: Dict[str, str]):
    """Encode a predicate as a z3 Bool expression, or None if unencodable."""
    if z3 is None or not isinstance(pred, dict):
        return None
    op = pred.get("op", "true")
    if op == "true":
        return z3.BoolVal(True)
    if op == "and":
        args = [a for a in pred.get("args", []) if isinstance(a, dict)]
        parts = [_to_z3(a, vars_, types) for a in args]
        return z3.And(*parts) if parts and all(p is not None for p in parts) else None
    if op == "or":
        args = [a for a in pred.get("args", []) if isinstance(a, dict)]
        parts = [_to_z3(a, vars_, types) for a in args]
        return z3.Or(*parts) if parts and all(p is not None for p in parts) else None
    if op == "not":
        args = pred.get("args", [])
        if not args:
            return None
        sub = _to_z3(args[0], vars_, types)
        return z3.Not(sub) if sub is not None else None

    f = pred.get("field")
    val = pred.get("value")
    if not f:
        return None
    ft = types.get(f)
    if ft not in ("int", "str"):
        return None

    v = vars_.get(f)
    if v is None:
        safe_name = _VAR_SAFE.sub("_", f)
        v = z3.Int(safe_name) if ft == "int" else z3.String(safe_name)
        vars_[f] = v

    if ft == "int":
        try:
            if op == "eq":
                return v == int(val)
            if op == "ne":
                return v != int(val)
            if op == "le":
                return v <= int(val)
            if op == "ge":
                return v >= int(val)
            if op == "in":
                return z3.Or(*[v == int(x) for x in val])
            if op == "not_in":
                return z3.And(*[v != int(x) for x in val])
        except (TypeError, ValueError):
            return None
        return None

    # ft == "str"
    if op == "eq":
        return v == z3.StringVal(str(val))
    if op == "ne":
        return v != z3.StringVal(str(val))
    if op == "in":
        return z3.Or(*[v == z3.StringVal(str(x)) for x in val])
    if op == "not_in":
        return z3.And(*[v != z3.StringVal(str(x)) for x in val])
    if op == "contains":
        return z3.Contains(v, str(val))
    if op == "glob":
        g = str(val)
        # only single trailing-* globs are provable; anything else -> conservative
        if g.endswith("*") and "*" not in g[:-1] and "?" not in g:
            return z3.PrefixOf(g[:-1], v)
        return None
    return None


def _proves_implication(a: dict, b: dict) -> bool:
    """True only when z3 PROVES ``a -> b``; otherwise False (fail-safe).

    Uses ``Solver.check()`` directly (not ``z3.prove``) because the return
    value of ``z3.prove`` changed across z3-solver major versions.
    """
    if not _HAS_Z3:
        return False
    types = _collect_field_types([a, b])
    vars_: Dict[str, Any] = {}
    za = _to_z3(a, vars_, types)
    zb = _to_z3(b, vars_, types)
    if za is None or zb is None:
        return False
    try:
        s = z3.Solver()
        s.set(timeout=2000)
        s.add(z3.Not(z3.Implies(za, zb)))
        return s.check() == z3.unsat  # negation unsat => implication valid
    except Exception:
        return False


def classify_update(new_rule: dict, current_rules: List[dict]) -> str:
    """Classify a proposed rule addition as ``narrowing`` or ``expansion``.

    Conservative (fail-safe): returns ``expansion`` unless the SMT solver can
    PROVE the update narrows the allowed action space. Narrowing auto-applies;
    expansion requires explicit approval.
    """
    if not _HAS_Z3:
        return "expansion"

    tool = new_rule.get("tool", "*")
    decision = new_rule.get("decision", "allow")
    pred = new_rule.get("predicate") or {}

    same = [r for r in (current_rules or [])
            if r.get("tool") == tool and r.get("decision") == decision]

    if decision == "allow":
        if not same:
            return "expansion"  # a brand-new allow rule grows the space
        # new allow is a narrowing iff new ⊆ old (it permits a subset)
        for old in same:
            if _proves_implication(pred, old.get("predicate") or {}):
                return "narrowing"
        return "expansion"
    else:  # deny
        if not same:
            return "narrowing"  # a brand-new deny rule restricts the space
        # new deny is a narrowing iff old ⊆ new (deny set grows)
        for old in same:
            if _proves_implication(old.get("predicate") or {}, pred):
                return "narrowing"
        return "expansion"


def predicate_fields(pred: Dict[str, Any]) -> set:
    """Return the set of field names referenced anywhere in a predicate."""
    if not isinstance(pred, dict):
        return set()
    op = pred.get("op", "true")
    if op in ("and", "or", "not"):
        out = set()
        for a in pred.get("args", []) or []:
            out |= predicate_fields(a)
        return out
    f = pred.get("field")
    return {f} if f else set()


def rules_cover(action_type: str, rules: List[dict]) -> bool:
    """True if any rule targets this action type (or uses the wildcard)."""
    return any((r.get("tool") in ("*", action_type)) for r in (rules or []))


def apply_update(rules: List[dict], new_rule: dict) -> List[dict]:
    """Append a rule to the policy, replacing an identical existing rule."""
    out = [r for r in (rules or []) if r != new_rule]
    out.append(new_rule)
    return out
