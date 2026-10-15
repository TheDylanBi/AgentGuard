"""Operator-declared empty values become explicit bounds, never a bypass."""
import json
from pydantic import TypeAdapter


def validate_empty_values(spec, fields):
    declarations = spec.get("optional_empty_values", {})
    if not isinstance(declarations, dict):
        raise ValueError("optional_empty_values must be an object")
    sensitive = spec["capability"].get("sensitive_params", [])
    for name, values in declarations.items():
        field = fields.get(name)
        if field is None or field.is_required() or field.default_factory is not None:
            raise ValueError("Empty-value declarations require a static optional argument")
        if name not in sensitive and "payload." + name not in sensitive:
            raise ValueError("Empty-value declarations must name a sensitive argument")
        if not isinstance(values, list) or not values:
            raise ValueError("Empty-value declarations require a nonempty list")
        adapter = TypeAdapter(field.rebuild_annotation())
        for value in values:
            if not (value is None or type(value) is str and value == ""
                    or type(value) is list and not value):
                raise ValueError("Only null, empty string and empty list may be declared empty")
            validated = adapter.validate_python(value, strict=True)
            if json.dumps(validated) != json.dumps(value):
                raise ValueError("Empty value must not require coercion")
        if not any(json.dumps(field.default) == json.dumps(v) for v in values):
            raise ValueError("Optional default must be one of the declared empty values")


# Backward-compatible import for existing adapters and tests.
from policy.tool_contract import complete_rules
