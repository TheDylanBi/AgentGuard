"""Reject demonstrably unusable initial policies without changing authority.

This is a bounded static check, not a proof that a model understood a task.
Unknown/complex predicates stay subject to the ordinary execution gates.
"""
import copy
import itertools
import re
from pydantic import TypeAdapter

from . import symbolic
from .tool_contract import typed_equal


def conjunction_atoms(predicate):
    if predicate.get("op") == "and":
        result = []
        for child in predicate["args"]:
            atoms = conjunction_atoms(child)
            if atoms is None:
                return None
            result.extend(atoms)
        return result
    return None if predicate.get("op") in {"or", "not"} else [predicate]


def finite_domains(predicate):
    """Exact finite bounds in a positive conjunction; None means unproved."""
    atoms = conjunction_atoms(predicate)
    if atoms is None:
        return None
    domains = {}
    for atom in atoms:
        if atom.get("op") not in {"eq", "in"}:
            continue
        values = [atom["value"]] if atom["op"] == "eq" else atom["value"]
        if any(isinstance(v, dict) and "$binding" in v for v in values):
            continue
        field = atom["field"]
        domains[field] = [v for v in values if field not in domains or
                          any(typed_equal(v, old) for old in domains[field])]
    return domains


def _literal_problem(value, adapter, prompt):
    try:
        validated = adapter.validate_python(value, strict=True)
        if not typed_equal(validated, value):
            return "rule_value_requires_coercion"
    except (TypeError, ValueError):
        return "rule_value_type_mismatch"
    if isinstance(value, str) and value not in prompt:
        if re.fullmatch(r"(?:user_provided_\w+|<[^<>]+>|\{\{[^{}]+\}\})", value, re.I):
            return "unresolved_placeholder"
        if value.lower() in {"null", "none"}:
            try:
                adapter.validate_python(None, strict=True)
            except (ValueError, TypeError):
                pass
            else:
                return "quoted_null_on_nullable_parameter"
    return None


def rule_semantic_errors(rules, contracts, *, prompt="", bindings=None):
    """Call after schema validation and trusted default/date compilation.

Never delete denies, convert strings, infer IDs, or create prerequisite grants.
Full deny coverage is checked only over finite allow domains (<=256 cases),
using the same tool-specific/wildcard precedence as the runtime.
"""
    bindings = bindings or {}
    errors = []
    for index, rule in enumerate(rules):
        tool = rule["tool"]
        contract = contracts.get(tool)
        def error(code, **details):
            item = {"rule_index": index, "code": code, **details}
            if item not in errors:
                errors.append(item)
        def walk(pred, positive=True):
            if pred["op"] in {"and", "or", "not"}:
                for child in pred["args"]:
                    walk(child, positive and pred["op"] == "and")
                return
            field, value = pred.get("field", ""), pred.get("value")
            def contains_reference(item):
                if isinstance(item, dict):
                    return "$binding" in item or any(contains_reference(v) for v in item.values())
                return isinstance(item, list) and any(contains_reference(v) for v in item)
            # Runtime materialization supports a reference only as the entire
            # eq value, never inside lists, JSON objects or source arguments.
            children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
            if any(contains_reference(child) for child in children):
                error("invalid_runtime_reference", field=field)
                return
            if isinstance(value, dict) and "$binding" in value:
                from .runtime_bindings import validate_reference
                try:
                    spec, source_args = validate_reference(value, bindings, contracts)
                    if (rule["decision"] != "allow" or not positive or pred["op"] != "eq"
                            or tool != spec["target_tool"] or field != "payload." + spec["target_field"]):
                        raise ValueError("Invalid reference position")
                except ValueError:
                    error("invalid_runtime_reference", field=field)
                    return
                source = spec["source_tool"]
                source_rules = [r for r in rules if r["tool"] == source and r["decision"] == "allow"]
                if not source_rules:
                    error("binding_missing_prerequisite_rule", source_tool=source)
                elif source_args is not None:
                    c = contracts[source]
                    fields = symbolic.action_fields(source, source_args.get(c.target_field, source), source_args)
                    for alias, key in c.aliases.items():
                        fields["payload." + alias] = source_args[key]
                    if symbolic.check_rules(source, fields, rules)[0] != "allow":
                        error("binding_prerequisite_outside_policy", source_tool=source)
                return
            if not contract or not field.startswith("payload.") or pred["op"] not in {"eq", "in"}:
                return
            name = contract.aliases.get(field[8:], field[8:])
            adapter = TypeAdapter(contract.parameters.model_fields[name].rebuild_annotation())
            for item in ([value] if pred["op"] == "eq" else value):
                problem = _literal_problem(item, adapter, prompt)
                if problem:
                    error(problem, field=field)
        walk(rule["predicate"])
        if rule["decision"] != "allow":
            continue
        domains = finite_domains(rule["predicate"])
        if domains is None:
            continue
        if any(not values for values in domains.values()):
            error("contradictory_parameter_bounds")
            continue
        # Restrict proof to predicates for which every referenced field is known.
        # Missing fields must NOT be treated as null during static evaluation.
        size = 1
        for values in domains.values():
            size *= len(values)
        if size > 256 or not symbolic.predicate_fields(rule["predicate"]) <= domains.keys():
            continue
        applicable = [r for r in rules if r["decision"] == "deny" and
                      r["tool"] in {tool, "*"} and
                      symbolic.predicate_fields(r["predicate"]) <= domains.keys()]
        if not applicable:
            continue
        candidates = [dict(zip(domains, values)) for values in itertools.product(*domains.values())]
        candidates = [f for f in candidates if symbolic.predicate_holds(rule["predicate"], f)]
        if candidates and all(symbolic.check_rules(tool, fields, [rule, *applicable])[0] == "deny"
                              for fields in candidates):
            error("allow_fully_shadowed_by_deny")
    return errors


def effect_consistency_errors(rules, effects, capabilities):
    """Cross-check declarations; never reinterpret or remove a prohibition."""
    forbidden = set(effects.get("forbidden_effects", []))
    return [{"rule_index": index, "code": "allowed_tool_has_forbidden_effect", "effect": effect}
            for index, rule in enumerate(rules) if rule["decision"] == "allow"
            and (effect := capabilities.get(rule["tool"], {}).get("effect_type")) in forbidden]


def quarantine_invalid_allows(rules, validate):
    """Narrow a fully parsed proposal, preserving EVERY deny byte-for-byte.

    Semantic errors in one allow must not poison an unrelated valid read. No
    structural/JSON errors are salvageable here. Revalidate after each removal
    so a removed prerequisite cannot leave an apparently valid binding behind.
    """
    indexed = list(enumerate(copy.deepcopy(rules)))
    quarantined = []
    for _ in range(len(rules) + 1):
        current = [r for _, r in indexed]
        errors = validate(current)
        if not errors:
            if quarantined and not any(r["decision"] == "allow" for r in current):
                return current, quarantined, [{"code": "no_valid_allow_after_quarantine"}]
            return current, quarantined, []
        invalid = {e.get("rule_index") for e in errors}
        if any(type(i) is not int or i < 0 or i >= len(current)
               or current[i]["decision"] != "allow" for i in invalid):
            return current, quarantined, errors
        quarantined.extend({"original_rule_index": original, "rule": copy.deepcopy(rule),
                            "errors": [e for e in errors if e.get("rule_index") == i]}
                           for i, (original, rule) in enumerate(indexed) if i in invalid)
        indexed = [item for i, item in enumerate(indexed) if i not in invalid]
    raise RuntimeError("Unreachable quarantine iteration limit")
