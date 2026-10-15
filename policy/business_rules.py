"""Operator-owned, deny-only business policy, independent of user intent.

Loaded once per engine instance. No request or approval can modify this policy.
An empty policy adds no restrictions and never grants permission.
"""
import hashlib
import json
import re
from pathlib import Path
from .parameter_constraints import validate_constraints, check_constraints


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate business policy JSON key")
        result[key] = value
    return result


class BusinessPolicy:
    def __init__(self, path=None):
        data = {"version": 1, "rules": []}
        if path is not None:
            with Path(path).open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("Business policy exceeds 1 MiB")
            data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object)
        self._validate(data)
        self._rules = data["rules"]
        self.fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True,
            ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    @staticmethod
    def _validate(data):
        if not isinstance(data, dict) or set(data) != {"version", "rules"}:
            raise ValueError("Business policy requires only version and rules")
        if type(data["version"]) is not int or data["version"] != 1:
            raise ValueError("Unsupported business policy version")
        rules = data["rules"]
        if not isinstance(rules, list) or len(rules) > 256:
            raise ValueError("Business policy requires at most 256 rules")
        seen = set()
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) - {"id", "actions", "mode", "parameter_constraints"}:
                raise ValueError("Unsupported business rule fields")
            identity = rule.get("id")
            if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identity) or identity in seen:
                raise ValueError("Business rule IDs must be unique and valid")
            seen.add(identity)
            actions = rule.get("actions")
            if not isinstance(actions, list) or not 1 <= len(actions) <= 128 or any(
                    not isinstance(a, str) or not re.fullmatch(r"\*|[A-Za-z0-9_-]{1,128}", a) for a in actions):
                raise ValueError("Business rule actions require exact action types or '*'")
            if len(set(actions)) != len(actions) or ("*" in actions and len(actions) != 1):
                raise ValueError("Duplicate or ambiguous business action selectors")
            mode = rule.get("mode")
            if mode == "deny":
                if "parameter_constraints" in rule:
                    raise ValueError("deny rules are unconditional; constraints require mode=require")
            elif mode == "require":
                constraints = rule.get("parameter_constraints")
                if not constraints:
                    raise ValueError("require rules need nonempty parameter constraints")
                validate_constraints(constraints)
            else:
                raise ValueError("Business rule mode must be deny or require")

    def check(self, action):
        for rule in self._rules:
            if "*" not in rule["actions"] and action.type not in rule["actions"]:
                continue
            why = ("Action prohibited by administrator business policy" if rule["mode"] == "deny"
                   else check_constraints(action, rule["parameter_constraints"]))
            if why:
                return {"verdict": "BLOCK", "rule": "business." + rule["id"], "reason": why}
        return None
