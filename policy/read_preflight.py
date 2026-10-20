"""Compile typed, task-initial read proposals into finite symbolic rules."""
import copy
import json
from .tool_contract import typed_equal


def read_call_schema(tools):
    choices, definitions = [], {}
    for index, tool in enumerate(tools):
        parameters = copy.deepcopy(tool["parameters"])
        local = parameters.pop("$defs", {})
        def rewrite(value):
            if isinstance(value, dict):
                return {key: (f"#/$defs/read_{index}_" + item[8:]
                              if key == "$ref" and isinstance(item, str) and item.startswith("#/$defs/")
                              else rewrite(item)) for key, item in value.items()}
            return [rewrite(v) for v in value] if isinstance(value, list) else value
        definitions.update({f"read_{index}_{key}": rewrite(value) for key, value in local.items()})
        parameters = rewrite(parameters)
        parameters.update(additionalProperties=False, required=list(parameters.get("properties", {})))
        choices.append({"type": "object", "additionalProperties": False,
            "required": ["tool", "arguments"], "properties": {
                "tool": {"enum": [tool["name"]]}, "arguments": parameters}})
    return {"type": "object", "additionalProperties": False, "required": ["calls"],
        "properties": {"calls": {"type": "array", "maxItems": 8, "items": {"anyOf": choices}}},
        "$defs": definitions}


def compile_read_calls(data, contracts):
    if not isinstance(data, dict) or set(data) != {"calls"} or not isinstance(data["calls"], list) or len(data["calls"]) > 8:
        raise ValueError("Invalid read calls envelope")
    rules = []
    for call in data["calls"]:
        if (not isinstance(call, dict) or set(call) != {"tool", "arguments"} or
                not isinstance(call["tool"], str) or call["tool"] not in contracts or
                not isinstance(call["arguments"], dict)):
            raise ValueError("Read call outside declared tools")
        contract = contracts[call["tool"]]
        args = call["arguments"]
        if not typed_equal(args, contract.normalize(args)):
            raise ValueError("Read arguments must include effective defaults without coercion")
        atoms = [{"op": "eq" if value is not None else "in", "field": "payload." + name,
                  "value": copy.deepcopy(value) if value is not None else [None]} for name, value in args.items()]
        rule = {"tool": call["tool"], "decision": "allow",
                "predicate": {"op": "and", "args": atoms} if atoms else {"op": "true"}}
        if not any(typed_equal(rule, old) for old in rules):
            rules.append(rule)
    return rules


def generate_read_rules(prompt, tools_hint, *, contracts, format_feedback=None):
    from .intent_anchor import _json_response, _output_failure
    context = json.loads(tools_hint)
    system = (
        "Select necessary READ-ONLY tool calls to prepare the ORIGINAL user's task. "
        "Return JSON calls with exact tool arguments, including optional defaults; no policy DSL. "
        "Only the original task can authorize a read. Never request unrelated resources, secrets or writes. "
        "Decide what information is needed, not which new object the user might create. "
        "For availability/conflict checks, read all appointments on the requested day; searching the new "
        "event's title cannot establish availability. For an event detail with unspecified source, relevant "
        "topic searches of calendar and mail may be necessary; avoid unrelated searches. "
        "For a reschedule, locate the existing event by its requested topic with date=null unless its OLD "
        "date is specified. The new date is not an old-date filter. A title is not an ID. "
        "For metadata filtering, use a suitable list or metadata tool within the user's scope, not content "
        "search pretending to support a sharing filter. A zero-argument tool uses arguments={}. "
        "Never guess missing IDs, addresses, dates or credentials. Return calls=[] if no read is needed. "
        "This stage sees no tool results or action proposals. It cannot change authorization after execution starts."
    )
    user = json.dumps({"original_task": prompt, "tools": context["tools"],
                      "trusted_calendar_context": context.get("trusted_calendar_context")}, ensure_ascii=False)
    if format_feedback:
        user += "\nReturn complete typed JSON with all effective arguments; no extra fields or explanation."
    data = _json_response(system, user, read_call_schema(context["tools"]))
    if data is None:
        return None
    try:
        return compile_read_calls(data, contracts)
    except (TypeError, ValueError):
        return _output_failure("invalid_read_calls")
