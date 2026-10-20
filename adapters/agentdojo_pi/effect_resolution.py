"""Host-only interpretation of reviewed effects; never read model-supplied state."""
import copy
from attestation.hashing import object_hash
from policy import symbolic
from policy.intent_validation import finite_domains
from policy.tool_contract import typed_equal


def validate_effect_declarations(spec, fields):
    resolver = spec.get("effect_recipients")
    mode = spec.get("dataflow_mode")
    if mode not in (None, "initial_arguments", "bound_resource_update", "declared_arguments"):
        raise ValueError("Unknown reviewed dataflow mode")
    origins = spec.get("dataflow_fields")
    if mode == "declared_arguments":
        if not isinstance(origins, dict) or set(origins) != set(fields):
            raise ValueError("Dataflow declarations must cover every effective argument")
        for declaration in origins.values():
            if (not isinstance(declaration, dict) or not isinstance(declaration.get("reason"), str)
                    or not declaration["reason"].strip()):
                raise ValueError("Dataflow fields require a review reason")
            if declaration.get("origin") == "initial":
                if set(declaration) != {"origin", "reason"}:
                    raise ValueError("Invalid initial argument declaration")
            elif declaration.get("origin") == "binding":
                names = declaration.get("bindings")
                if (set(declaration) != {"origin", "reason", "bindings"} or not isinstance(names, list)
                        or not 1 <= len(names) <= 128 or any(not isinstance(n, str) or not n for n in names)
                        or len(set(names)) != len(names)):
                    raise ValueError("Invalid argument binding allowlist")
            else:
                raise ValueError("Unknown argument origin")
    elif origins is not None:
        raise ValueError("Dataflow fields require declared_arguments mode")
    if (resolver or mode) and not spec.get("schema_hash"):
        raise ValueError("Effect/dataflow declarations require pinned schema")
    if resolver is not None:
        if (not isinstance(resolver, dict) or set(resolver) != {
                "collection_path", "argument", "recipients_field", "reason"} or
                not isinstance(resolver["argument"], str) or resolver["argument"] not in fields or
                not isinstance(resolver["collection_path"], list) or
                not 1 <= len(resolver["collection_path"]) <= 8 or
                any(not isinstance(v, str) or not v for v in resolver["collection_path"]) or
                not isinstance(resolver["recipients_field"], str) or not resolver["recipients_field"] or
                not isinstance(resolver["reason"], str) or not resolver["reason"].strip()):
            raise ValueError("Invalid reviewed recipient resolver")
    if mode == "bound_resource_update" and resolver is None:
        raise ValueError("Bound resource dataflow requires an effect resolver")


def resolve_recipients(spec, arguments, environment):
    resolver = spec.get("effect_recipients")
    if resolver is None:
        return None, None
    collection = environment
    for part in resolver["collection_path"]:
        if not isinstance(collection, dict) or part not in collection:
            raise ValueError("Effect resource collection unavailable")
        collection = collection[part]
    key = arguments.get(resolver["argument"])
    if not isinstance(key, str) or not isinstance(collection, dict) or key not in collection:
        raise ValueError("Effect resource unavailable")
    resource = collection[key]
    recipients = resource.get(resolver["recipients_field"]) if isinstance(resource, dict) else None
    if not isinstance(recipients, list) or any(not isinstance(v, str) or not v for v in recipients):
        raise ValueError("Effect recipients unavailable")
    return list(dict.fromkeys(recipients)), {"resource_hash": object_hash(resource),
        "recipients_hash": object_hash(recipients), "argument": resolver["argument"]}


def validate_argument_bindings(tool, spec, bindings):
    for field, declaration in spec.get("dataflow_fields", {}).items():
        for name in declaration.get("bindings", []):
            binding = bindings.get(name)
            if not binding or binding["target_tool"] != tool or binding["target_field"] != field:
                raise ValueError("Dataflow binding must declare this exact target tool and field")


def argument_proof(action, arguments, contract, rules, binding_records, spec, state_hash, effect_record):
    """Prove finite parameter origin, not that a natural-language plan is correct.

    `rules` is the host materialization of immutable initial rules. No model
    proposal, tool result text, or policy feedback can add an allowed value.
    Direct taint and all other gates remain mandatory after this proof.
    """
    mode = spec.get("dataflow_mode")
    if not mode or contract.check(action, rules, spec["capability"]) is not None:
        return None
    fields = symbolic.action_fields(action.type, action.target, action.payload)
    decision, matched = symbolic.check_rules(action.type, fields, rules)
    if decision != "allow" or not matched or matched["tool"] != action.type:
        return None
    domains = finite_domains(matched["predicate"])
    if domains is None:
        return None
    for name, value in arguments.items():
        bounds = domains.get("payload." + name, [])
        for alias, source in contract.aliases.items():
            if source == name:
                bounds += domains.get("payload." + alias, [])
        if not any(typed_equal(value, bound) for bound in bounds):
            return None
    records = [r for r in binding_records if r["target_tool"] == action.type and r["state_hash"] == state_hash]
    if mode == "initial_arguments" and records:
        return None  # No claim about dynamic values for argument-only tools.
    if mode == "declared_arguments":
        for name, value in arguments.items():
            declaration = spec["dataflow_fields"][name]
            field_records = [r for r in records if r["target_field"] == name]
            if declaration["origin"] == "initial":
                if field_records:
                    return None
            elif not field_records or any(r["binding"] not in declaration["bindings"] or
                    r["value_hash"] != object_hash(value) for r in field_records):
                return None
    if mode == "bound_resource_update":
        if effect_record is None or not any(r.get("target_field") == effect_record["argument"] and
                r["value_hash"] == object_hash(arguments[effect_record["argument"]]) for r in records):
            return None
    return {"kind": mode, "arguments_hash": object_hash(arguments), "state_hash": state_hash,
            "rule_hash": object_hash(matched), "effect": copy.deepcopy(effect_record),
            "bindings": copy.deepcopy(records)}
