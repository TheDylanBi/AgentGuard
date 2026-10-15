"""Task-local, declaration-driven value binding. No authority from observations.

An initial allow rule must explicitly request a declared binding using an eq
value {"$binding": "id"}. Only successful, authorized host observations can
materialize it. Every resulting call still needs ordinary authorization.
"""
import copy
import json
import time
from pydantic import TypeAdapter
from attestation.hashing import object_hash


def json_value(value):
    return json.loads(TypeAdapter(object).dump_json(value, warnings="error"))


def extract_unique(value, path):
    values = [value]
    for part in path:
        out = []
        for item in values:
            if part == "*" and isinstance(item, list):
                out.extend(item)
            elif isinstance(item, dict) and part in item:
                out.append(item[part])
            else:
                return None, False
        values = out
        if len(values) > 1024:
            return None, False
    # Even identical values on two objects need a trusted selection rule.
    return (values[0], True) if len(values) == 1 else (None, False)


class RuntimeBindings:
    def __init__(self, declarations, contracts, *, task_id, clock=time.monotonic):
        self.declarations = copy.deepcopy(declarations or {})
        self.contracts, self.task_id, self.clock = contracts, task_id, clock
        self.observations, self.used, self.last = {}, {}, []
        if not isinstance(self.declarations, dict) or len(self.declarations) > 128:
            raise ValueError("Invalid binding declarations")
        keys = {"target_tool", "target_field", "source_tool", "source_path", "source_arguments",
                "ttl_seconds", "max_uses", "reason"}
        for name, spec in self.declarations.items():
            if not isinstance(name, str) or not name or not isinstance(spec, dict) or set(spec) != keys:
                raise ValueError("Binding declaration requires an exact reviewed schema")
            source, target = spec["source_tool"], spec["target_tool"]
            if source not in contracts or target not in contracts or spec["target_field"] not in contracts[target].fields:
                raise ValueError("Binding refers to unknown tool/parameter")
            if not isinstance(spec["reason"], str) or not spec["reason"].strip():
                raise ValueError("Binding requires an operator review reason")
            path = spec["source_path"]
            if not isinstance(path, list) or len(path) > 16 or any(not isinstance(p, str) or not p for p in path):
                raise ValueError("Binding path must contain object keys or list wildcard")
            args = spec["source_arguments"]
            if not isinstance(args, dict) or set(args) - set(contracts[source].fields):
                raise ValueError("Unknown source argument constraint")
            json.dumps(args, allow_nan=False)
            for key in ("ttl_seconds", "max_uses"):
                if type(spec[key]) is not int or not 1 <= spec[key] <= 600:
                    raise ValueError("Binding limits must be positive bounded integers")

    def observe(self, tool, arguments, result, *, call_id, state_hash):
        """Trusted host only; call after successful authorization AND execution."""
        from .tool_contract import typed_equal
        for name, spec in self.declarations.items():
            if spec["source_tool"] != tool or any(
                    key not in arguments or not typed_equal(arguments[key], value)
                    for key, value in spec["source_arguments"].items()):
                continue
            try:
                value, unique = extract_unique(json_value(result), spec["source_path"])
                if not unique:
                    self.observations[name] = None
                    continue
                field = self.contracts[spec["target_tool"]].parameters.model_fields[spec["target_field"]]
                validated = TypeAdapter(field.rebuild_annotation()).validate_python(value, strict=True)
                if not typed_equal(json_value(validated), value):
                    raise ValueError("Binding would coerce a value")
            except (ValueError, TypeError):
                self.observations[name] = None
                continue
            record = {"value": copy.deepcopy(value), "call_id": call_id, "state_hash": state_hash,
                      "created": self.clock(), "source_arguments_hash": object_hash(arguments)}
            # Multiple observations are ambiguous; don't choose the most recent
            # result or reset the lifetime/use limit by repeatedly querying.
            if name in self.observations:
                self.observations[name] = None
            else:
                self.observations[name] = record

    def materialize(self, rules, *, state_hash):
        """Return an ephemeral rule view; never modify the initial rule set."""
        self.last = []
        result = []
        for rule in copy.deepcopy(rules):
            if rule.get("decision") != "allow":
                def has_reference(value):
                    if isinstance(value, dict):
                        return "$binding" in value or any(has_reference(v) for v in value.values())
                    return isinstance(value, list) and any(has_reference(v) for v in value)
                if has_reference(rule):
                    raise ValueError("Dynamic references are forbidden in deny rules")
                result.append(rule)
                continue
            records = []
            def walk(pred, positive=True):
                if not isinstance(pred, dict):
                    return False
                if pred.get("op") in ("and", "or", "not"):
                    return all([walk(p, positive and pred["op"] == "and") for p in pred.get("args", [])])
                value = pred.get("value")
                if not isinstance(value, dict) or "$binding" not in value:
                    return True
                name = value.get("$binding")
                spec = self.declarations.get(name) if isinstance(name, str) else None
                record = self.observations.get(name) if isinstance(name, str) else None
                if (set(value) != {"$binding"} or not positive or pred.get("op") != "eq" or not spec
                        or rule.get("tool") != spec["target_tool"]
                        or pred.get("field") != "payload." + spec["target_field"] or not record
                        or record["state_hash"] != state_hash
                        or self.clock() - record["created"] >= spec["ttl_seconds"]
                        or self.used.get(name, 0) >= spec["max_uses"]):
                    return False
                pred["value"] = copy.deepcopy(record["value"])
                # eq-null does not count as finite coverage in the core DSL.
                if pred["value"] is None:
                    pred.update(op="in", value=[None])
                records.append({"binding": name, "task_id": self.task_id,
                                "source_call_id": record["call_id"], "state_hash": state_hash,
                                "value_hash": object_hash(record["value"]), "target_tool": rule["tool"]})
                return True
            if walk(rule.get("predicate")):
                result.append(rule)
                self.last.extend(records)
        return result

    def consume(self, tool):
        # Conservatively consume every resolved binding for this target tool.
        for name in {r["binding"] for r in self.last if r["target_tool"] == tool}:
            self.used[name] = self.used.get(name, 0) + 1

    def diagnostics(self):
        return {"declared": sorted(self.declarations), "observed": sorted(self.observations),
                "invalid_or_ambiguous": sorted(k for k, v in self.observations.items() if v is None),
                "used": dict(self.used)}
