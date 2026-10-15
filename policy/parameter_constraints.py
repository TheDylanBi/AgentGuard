"""Small, strict administrator constraint dialect (not full JSON Schema).

Bare fields address payload keys; payload.a.b addresses nested objects.
Constraints are conjunctive, required by default, and never coerce values.
"""
import math
import re

MISSING = object()
TYPES = {"string", "number", "integer", "boolean", "array"}
BOUNDS = {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"}
LENGTHS = {"minLength", "maxLength", "minItems", "maxItems"}
KEYS = {"type", "enum", "const", "required", "items"} | BOUNDS | LENGTHS


def number(value):
    return type(value) is int or (type(value) is float and math.isfinite(value))


def scalar(value):
    return type(value) in (str, bool) or number(value)


def equal(a, b):
    # Python's True == 1 must not grant access.
    return (type(a) is type(b) or (number(a) and number(b))) and a == b


def validate_rule(rule, depth=0, item=False):
    if depth > 8 or not isinstance(rule, dict) or not rule or set(rule) - KEYS:
        raise ValueError("Invalid or unsupported parameter constraint")
    if "required" in rule and (type(rule["required"]) is not bool or item):
        raise ValueError("required must be boolean and is only valid on fields")
    kind = rule.get("type")
    if "type" in rule and (not isinstance(kind, str) or kind not in TYPES):
        raise ValueError("Unsupported parameter type")
    if set(rule) == {"required"}:
        raise ValueError("Constraint must restrict a value, not only presence")
    for key in BOUNDS & rule.keys():
        if not number(rule[key]) or kind not in (None, "number", "integer"):
            raise ValueError("Numeric bounds require finite numbers and a numeric type")
    for key in LENGTHS & rule.keys():
        expected = "string" if key.endswith("Length") else "array"
        if type(rule[key]) is not int or rule[key] < 0 or kind != expected:
            raise ValueError("Length bounds require nonnegative integers and explicit matching type")
    for lo, hi in (("minimum", "maximum"), ("minLength", "maxLength"), ("minItems", "maxItems")):
        if lo in rule and hi in rule and rule[lo] > rule[hi]:
            raise ValueError("Contradictory parameter bounds")
    for lo in ("minimum", "exclusiveMinimum"):
        for hi in ("maximum", "exclusiveMaximum"):
            if lo in rule and hi in rule and (rule[lo] > rule[hi] or
                    rule[lo] == rule[hi] and (lo.startswith("exclusive") or hi.startswith("exclusive"))):
                raise ValueError("Empty numeric interval")
    if "enum" in rule:
        if not isinstance(rule["enum"], list) or not rule["enum"] or len(rule["enum"]) > 1024 or not all(scalar(v) for v in rule["enum"]):
            raise ValueError("enum must contain 1..1024 finite scalar values")
    if "const" in rule and not scalar(rule["const"]):
        raise ValueError("const must be a finite scalar")
    if "items" in rule:
        if kind != "array":
            raise ValueError("items requires array type")
        validate_rule(rule["items"], depth + 1, item=True)


def validate_constraints(constraints):
    if not isinstance(constraints, dict) or len(constraints) > 128:
        raise ValueError("parameter_constraints must be a map with at most 128 fields")
    seen = set()
    for field, rule in constraints.items():
        if not isinstance(field, str) or len(field) > 256:
            raise ValueError("Invalid constrained field")
        if field == "target":
            path = field
        elif field.startswith("payload."):
            path = field
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", field) and field != "payload":
            path = "payload." + field
        else:
            raise ValueError("Use target, a bare payload key, or payload.a.b")
        if path != "target" and not re.fullmatch(r"payload(?:\.[A-Za-z_][A-Za-z0-9_-]*)+", path):
            raise ValueError("Unsupported parameter path")
        if path in seen:
            raise ValueError("Duplicate parameter aliases")
        seen.add(path)
        validate_rule(rule)
    return constraints


def violation(value, rule):
    if value is MISSING:
        return "missing required parameter" if rule.get("required", True) else None
    kind = rule.get("type")
    checks = {"string": lambda: type(value) is str,
              "number": lambda: number(value),
              "integer": lambda: type(value) is int,
              "boolean": lambda: type(value) is bool,
              "array": lambda: type(value) is list}
    if kind and not checks[kind]():
        return "parameter type mismatch"
    if "const" in rule and not equal(value, rule["const"]):
        return "parameter differs from required constant"
    if "enum" in rule and not any(equal(value, v) for v in rule["enum"]):
        return "parameter outside allowed values"
    if BOUNDS & rule.keys():
        if not number(value):
            return "numeric parameter required"
        if ("minimum" in rule and value < rule["minimum"] or
            "maximum" in rule and value > rule["maximum"] or
            "exclusiveMinimum" in rule and value <= rule["exclusiveMinimum"] or
            "exclusiveMaximum" in rule and value >= rule["exclusiveMaximum"]):
            return "parameter outside numeric bounds"
    for key in LENGTHS & rule.keys():
        if (key.startswith("min") and len(value) < rule[key] or
                key.startswith("max") and len(value) > rule[key]):
            return "parameter outside length bounds"
    if "items" in rule:
        for v in value:
            why = violation(v, rule["items"])
            if why:
                return "array item: " + why
    return None


def check_constraints(action, constraints):
    """Return a value-free failure reason; malformed offline declarations fail closed."""
    try:
        validate_constraints(constraints)
    except (TypeError, ValueError, RecursionError):
        return "Invalid capability parameter constraints"
    for field, rule in constraints.items():
        if field == "target":
            value = getattr(action, "target", MISSING)
        else:
            path = field.removeprefix("payload.").split(".")
            value = getattr(action, "payload", {})
            for part in path:
                if not isinstance(value, dict):
                    # Optional leaves must not hide malformed parent containers.
                    return f"{field}: invalid parent object"
                value = value.get(part, MISSING)
                if value is MISSING:
                    break
        why = violation(value, rule)
        if why:
            return f"{field}: {why}"
    return None
