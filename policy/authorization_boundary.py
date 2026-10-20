"""Compile an initial task boundary to the existing deny-first policy language.

No tool output or proposed action enters this compiler. Classification comes
from reviewed contracts. Unresolved grants never become broad allow rules.
"""
import copy
import json
from pydantic import TypeAdapter
from .tool_contract import typed_equal
from .runtime_bindings import validate_reference
from .rule_validation import rule_schema_errors


def compile_boundary(boundary, contracts, bindings):
    try:
        if len(json.dumps(boundary, allow_nan=False)) > 262144:
            raise ValueError("Boundary exceeds size limit")
    except (TypeError, RecursionError) as exc:
        raise ValueError("Boundary must be bounded JSON") from exc
    if (not isinstance(boundary, dict) or set(boundary) != {"version", "grants", "denies"}
            or type(boundary["version"]) is not int or boundary["version"] != 1):
        raise ValueError("Invalid authorization boundary envelope")
    if any(not isinstance(boundary[k], list) or len(boundary[k]) > 128 for k in ("grants", "denies")):
        raise ValueError("Boundary clauses must be bounded lists")
    denies = copy.deepcopy(boundary["denies"])
    if (any(not isinstance(r, dict) or r.get("decision") != "deny" for r in denies)
            or rule_schema_errors(denies, contracts)):
        raise ValueError("Invalid boundary deny; never discard or repair a deny")
    rules, unresolved, provenance = [], [], []
    for index, grant in enumerate(boundary["grants"]):
        if (not isinstance(grant, dict) or set(grant) != {"tool", "purpose", "parameters"}
                or not isinstance(grant["tool"], str) or grant["tool"] not in contracts
                or not isinstance(grant["purpose"], str) or not 1 <= len(grant["purpose"]) <= 2000):
            raise ValueError("Invalid boundary grant")
        tool = grant["tool"]
        contract = contracts[tool]
        parameters = grant["parameters"]
        if not isinstance(parameters, dict) or set(parameters) != set(contract.fields):
            raise ValueError("Boundary must describe every effective parameter, including defaults")
        atoms, missing, origins = [], [], {}
        for field, bound in parameters.items():
            if not isinstance(bound, dict):
                raise ValueError("Invalid parameter boundary")
            kind = bound.get("kind")
            role = contract.fields[field]["role"]
            origins[field] = {"role": role, "kind": kind}
            if kind == "values" and set(bound) == {"kind", "values"}:
                values = bound["values"]
                if not isinstance(values, list) or not 1 <= len(values) <= 32:
                    raise ValueError("Parameter values must be a nonempty finite set")
                adapter = TypeAdapter(contract.parameters.model_fields[field].rebuild_annotation())
                def has_reference(value):
                    if isinstance(value, dict):
                        return "$binding" in value or any(has_reference(v) for v in value.values())
                    return isinstance(value, list) and any(has_reference(v) for v in value)
                for value in values:
                    if has_reference(value):
                        raise ValueError("Runtime references must use an explicit binding boundary")
                    if not typed_equal(adapter.validate_python(value, strict=True), value):
                        raise ValueError("Boundary parameter requires coercion")
                atoms.append({"op": "in", "field": "payload." + field, "value": copy.deepcopy(values)})
            elif kind == "binding" and set(bound) == {"kind", "reference"}:
                if role == "execution":
                    raise ValueError("Executable parameters require initial finite values, not external binding")
                spec, _ = validate_reference(bound["reference"], bindings, contracts)
                if spec["target_tool"] != tool or spec["target_field"] != field:
                    raise ValueError("Boundary binding targets a different parameter")
                atoms.append({"op": "eq", "field": "payload." + field, "value": copy.deepcopy(bound["reference"])})
            elif kind == "unresolved" and set(bound) == {"kind", "reason"}:
                if not isinstance(bound["reason"], str) or not 1 <= len(bound["reason"]) <= 1000:
                    raise ValueError("Unresolved parameter requires a bounded explanation")
                missing.append({"field": field, "role": role, "reason": bound["reason"]})
            else:
                raise ValueError("Unknown boundary kind or extra authority fields")
        provenance.append({"grant_index": index, "tool": tool, "parameters": origins, "executable": not missing})
        if missing:
            unresolved.append({"grant_index": index, "tool": tool, "parameters": missing})
        else:
            rules.append({"tool": tool, "decision": "allow",
                          "predicate": {"op": "and", "args": atoms} if atoms else {"op": "true"}})
    # Existing downstream semantic validation, effect checks and runtime gates
    # remain mandatory. The compiler does not claim to verify user intent.
    return rules + denies, {"version": 1, "unresolved": unresolved, "grants": provenance}
