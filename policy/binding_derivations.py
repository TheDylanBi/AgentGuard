"""Bounded host derivations. Untrusted input selects data, never policy/code.

Configuration comes from a reviewed binding declaration, not the model call.
The resulting exact value still needs the initial binding reference and every
ordinary execution gate. This is not an arbitrary text-generation verifier.
"""
import copy
import json

from pydantic import TypeAdapter

from .tool_contract import typed_equal


def validate_derivation(config, contract, target_field):
    if not isinstance(config, dict):
        raise ValueError("Derivation must be a reviewed object")
    kind = config.get("kind")
    if kind == "text_template":
        if set(config) != {"kind", "parts", "max_chars"}:
            raise ValueError("Invalid text template declaration")
        if contract.parameters.model_fields[target_field].annotation is not str:
            raise ValueError("Text template requires a string parameter")
        if type(config["max_chars"]) is not int or not 1 <= config["max_chars"] <= 16384:
            raise ValueError("Text output requires a bounded size")
        parts = config["parts"]
        if not isinstance(parts, list) or not 1 <= len(parts) <= 32:
            raise ValueError("Invalid template parts")
        for part in parts:
            if not isinstance(part, dict):
                raise ValueError("Invalid template part")
            if set(part) == {"literal"}:
                if not isinstance(part["literal"], str) or len(part["literal"]) > config["max_chars"]:
                    raise ValueError("Invalid template literal")
            elif set(part) == {"path"}:
                path = part["path"]
                if (not isinstance(path, list) or len(path) > 16 or
                        any(not isinstance(p, str) or not p or p == "*" for p in path)):
                    raise ValueError("Template paths must name object fields")
            else:
                raise ValueError("Unknown template operation")
        if not any("path" in part for part in parts):
            raise ValueError("A source binding template must actually use its source")
    elif kind == "structured_call":
        if set(config) != {"kind", "bounds"}:
            raise ValueError("Invalid delegation declaration")
        bounds = config["bounds"]
        if not isinstance(bounds, dict) or set(bounds) != set(contract.fields):
            raise ValueError("Delegation must bound every effective argument")
        # Bounded JSON data, not predicates, scripts, glob grants or defaults.
        try:
            encoded = json.dumps(bounds, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("Invalid delegation bounds") from exc
        if len(encoded) > 65536:
            raise ValueError("Delegation bounds too large")
        for field, values in bounds.items():
            if not isinstance(values, list) or not 1 <= len(values) <= 32:
                raise ValueError("Delegation fields require finite alternatives")
            adapter = TypeAdapter(contract.parameters.model_fields[field].rebuild_annotation())
            for value in values:
                if not typed_equal(adapter.validate_python(value, strict=True), value):
                    raise ValueError("Delegation bounds require exact parameter types")
    else:
        raise ValueError("Unknown derivation kind")


def derive_value(value, config, contract, target_field):
    """Return only exact derived data. Never execute or compile document code."""
    from .runtime_bindings import extract_unique
    if config["kind"] == "text_template":
        parts, size = [], 0
        for part in config["parts"]:
            if "literal" in part:
                text = part["literal"]
            else:
                text, found = extract_unique(value, part["path"])
                if not found or not isinstance(text, str):
                    raise ValueError("Template source field missing or not text")
            size += len(text)
            if size > config["max_chars"]:
                raise ValueError("Derived text exceeds declared limit")
            parts.append(text)
        return "".join(parts)
    # Accept an already structured object only. No parsing code fences, JSON
    # embedded in prose, or requests to reinterpret instructions as authority.
    if (not isinstance(value, dict) or set(value) != {"tool", "arguments"}
            or value["tool"] != contract.name or not isinstance(value["arguments"], dict)):
        raise ValueError("Document must contain the exact declared structured call")
    arguments = value["arguments"]
    if set(arguments) != set(contract.fields):
        raise ValueError("Delegation must specify every effective argument")
    if not typed_equal(arguments, contract.normalize(arguments)):
        raise ValueError("Delegated arguments cannot be coerced")
    for field, alternatives in config["bounds"].items():
        if not any(typed_equal(arguments[field], candidate) for candidate in alternatives):
            raise ValueError("Document request exceeds the reviewed envelope")
    return copy.deepcopy(arguments[target_field])
