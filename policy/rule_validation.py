"""Schema-bound validation of initial intent proposals, never call-derived grants."""
import json
from .intent_anchor import _sanitize_rules


def rule_schema_errors(rules, contracts):
    """Return structural errors only; incomplete authority remains denied at runtime."""
    if not isinstance(rules, list) or (rules and not _sanitize_rules(rules)):
        return [{"code": "invalid_rule_structure"}]
    errors = []
    for index, rule in enumerate(rules):
        tool = rule.get("tool")
        selected = list(contracts.values()) if tool == "*" else [contracts[tool]] if isinstance(tool, str) and tool in contracts else []
        if not selected:
            errors.append({"rule_index": index, "code": "unknown_tool"})
            continue
        # A wildcard may reference only fields available on every matching tool.
        allowed = set.intersection(*({"type", "target"} |
            {"payload." + f for f in (*c.fields, *c.aliases)} for c in selected))
        def walk(pred):
            if pred["op"] in ("and", "or", "not"):
                for child in pred["args"]:
                    walk(child)
            elif pred["op"] != "true" and pred["field"] not in allowed:
                errors.append({"rule_index": index, "code": "unknown_field_path",
                               "allowed_fields": sorted(allowed)})
        walk(rule["predicate"])
    return errors


def repair_constraints_preserved(original, replacement, contracts):
    """Only repair paths / conjoin existing positive conditions, never invent grants.

    Ambiguous Boolean rewrites are deliberately unsupported. All original allow
    conditions for a tool must survive together in every repaired allow branch.
    No rule is changed by this check; the model must return a compliant proposal.
    """
    def atoms(pred, contract, fix_paths=False):
        if pred.get("op") == "and":
            result = set()
            for child in pred["args"]:
                result |= atoms(child, contract, fix_paths)
            return result
        if pred.get("op") in ("or", "not"):
            raise ValueError("Ambiguous Boolean rewrite")
        leaf = dict(pred)
        field = leaf.get("field")
        if fix_paths and field not in ("type", "target") and field in (*contract.fields, *contract.aliases):
            leaf["field"] = "payload." + field
        return {json.dumps(leaf, sort_keys=True, allow_nan=False)}
    try:
        required = {}
        for rule in original:
            if rule["decision"] == "allow":
                tool = rule["tool"]
                required.setdefault(tool, set()).update(atoms(rule["predicate"], contracts[tool], True))
        for rule in replacement:
            if rule["decision"] == "allow":
                tool = rule["tool"]
                if tool not in required or atoms(rule["predicate"], contracts[tool]) != required[tool]:
                    return False
        serialized = {json.dumps(r, sort_keys=True, allow_nan=False) for r in replacement}
        return all(json.dumps(r, sort_keys=True, allow_nan=False) in serialized
                   for r in original if r["decision"] == "deny")
    except (KeyError, ValueError, TypeError):
        return False
