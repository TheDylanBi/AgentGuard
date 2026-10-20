"""Strict final JSON envelopes and opt-in schemas; no repairs to policy values."""
import json
import math
import re
import copy


class IntentOutputError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class IntentStageError(RuntimeError):
    """An expected model/configuration failure, distinct from execution faults."""
    def __init__(self, diagnostic):
        self.diagnostic = diagnostic
        super().__init__("Intent stage failed: " + json.dumps(diagnostic))

    @property
    def task_local(self):
        # A diagnosed policy conflict is not evidence of provider unavailability.
        return (self.diagnostic.get("status") in {"invalid_rule_schema", "invalid_rule_semantics"} or
                (self.diagnostic.get("status") == "invalid_output" and
                 self.diagnostic.get("http_status") == 200 and
                 self.diagnostic.get("output_error") == "truncated_output" and
                 self.diagnostic.get("finish_reason") == "length"))


def parse_final_json(content):
    if not isinstance(content, str) or not content.strip():
        raise IntentOutputError("empty_output")
    text = content.strip()
    # Remove only a complete leading reasoning envelope. Never search its JSON
    # for a usable allow rule or salvage part of an unfinished final object.
    if text.startswith("<think>"):
        _, marker, text = text.partition("</think>")
        if not marker:
            raise IntentOutputError("unfinished_reasoning")
        text = text.strip()
    if text.startswith("```"):
        fenced = re.fullmatch(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL | re.IGNORECASE)
        if not fenced:
            raise IntentOutputError("invalid_json_envelope")
        text = fenced[1].strip()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise IntentOutputError("duplicate_json_key")
            result[key] = value
        return result
    def nonfinite(_):
        raise IntentOutputError("nonfinite_json_number")
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise IntentOutputError("nonfinite_json_number")
        return number
    try:
        data = json.loads(text, object_pairs_hook=unique, parse_constant=nonfinite, parse_float=finite_float)
    except json.JSONDecodeError:
        raise IntentOutputError("invalid_json_syntax") from None
    except RecursionError:
        raise IntentOutputError("json_depth_exceeded") from None
    except IntentOutputError:
        raise
    except ValueError:
        raise IntentOutputError("invalid_json_value") from None
    if not isinstance(data, dict):
        raise IntentOutputError("expected_json_object")
    return data


_OPS = ["true", "and", "or", "not", "eq", "ne", "le", "ge", "in", "not_in", "glob", "contains"]
RULES_SCHEMA = {
    "type": "object", "required": ["rules"], "additionalProperties": False,
    "properties": {"rules": {"type": "array", "items": {
        "type": "object", "required": ["tool", "decision", "predicate"], "additionalProperties": False,
        "properties": {"tool": {"type": "string"}, "decision": {"enum": ["allow", "deny"]},
                       "reason": {"type": "string"}, "predicate": {"$ref": "#/$defs/predicate"}}}}},
    "$defs": {"predicate": {
        "type": "object", "required": ["op"], "additionalProperties": False,
        "properties": {"op": {"enum": _OPS}, "field": {"type": "string"}, "value": {},
                       "args": {"type": "array", "items": {"$ref": "#/$defs/predicate"}}}}}
}
EFFECT_LISTS = ("allowed_recipients", "allowed_targets", "allowed_data_types", "allowed_operations", "forbidden_effects")
EFFECTS_SCHEMA = {"type": "object", "required": list(EFFECT_LISTS), "additionalProperties": False,
    "properties": {**{k: {"type": "array", "items": {"type": "string"}} for k in EFFECT_LISTS},
                   "max_items": {"type": ["integer", "null"], "minimum": 0}}}
DANGER_SCHEMA = {"type": "object", "required": ["dangerous", "reason"], "additionalProperties": False,
    "properties": {"dangerous": {"type": "boolean"}, "reason": {"type": "string"}}}


def rules_schema_for_tools(tools_hint):
    """Constrain names/paths from trusted static schemas, never task answers."""
    schema = copy.deepcopy(RULES_SCHEMA)
    if isinstance(tools_hint, str):
        try:
            tools_hint = json.loads(tools_hint)
        except (ValueError, TypeError):
            return schema
    if not isinstance(tools_hint, dict) or not isinstance(tools_hint.get("tools"), list):
        return schema
    tools = tools_hint["tools"]
    if not tools:
        return schema
    choices, definitions = [], {}
    for index, tool in enumerate([*tools, {"name": "*", "parameters": {"properties": {}}}]):
        name = tool["name"]
        fields = {"type", "target"}
        fields.update("payload." + key for key in tool["parameters"].get("properties", {}))
        aliases = tools_hint.get("policy_mapping", {}).get(name, {}).get("policy_aliases", {})
        fields.update("payload." + key for key in aliases)
        key = f"predicate_{index}"
        predicate = copy.deepcopy(RULES_SCHEMA["$defs"]["predicate"])
        predicate["properties"]["field"] = {"enum": sorted(fields)}
        predicate["properties"]["args"]["items"]["$ref"] = "#/$defs/" + key
        definitions[key] = predicate
        rule = copy.deepcopy(RULES_SCHEMA["properties"]["rules"]["items"])
        rule["properties"]["tool"] = {"enum": [name]}
        rule["properties"]["predicate"] = {"$ref": "#/$defs/" + key}
        choices.append(rule)
    schema["$defs"] = definitions
    schema["properties"]["rules"]["items"] = {"anyOf": choices}
    return schema
