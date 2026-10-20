"""Task-local, declaration-driven value binding. No authority from observations.

An initial allow rule must explicitly request a declared binding using an eq
value {"$binding": "id"}. Only successful, authorized host observations can
materialize it. Every resulting call still needs ordinary authorization.
"""
import copy
import json
import math
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


def validate_selection(selection):
    """Selection is operator-reviewed metadata, never a tool-output instruction."""
    if not isinstance(selection, dict) or selection.get("mode") not in ("where", "min", "max"):
        raise ValueError("Invalid binding selection")
    required = {"mode", "field", "project"}
    if selection["mode"] == "where":
        required.add("value")
    if set(selection) != required:
        raise ValueError("Selection requires an exact reviewed schema")
    for key in ("field", "project"):
        path = selection[key]
        if (not isinstance(path, list) or not 1 <= len(path) <= 16
                or any(not isinstance(p, str) or not p or p == "*" for p in path)):
            raise ValueError("Selection paths must name object fields")
    if "value" in selection:
        json.dumps(selection["value"], allow_nan=False)


def extract_selected(value, path, selection=None):
    """Select one record from a bounded list; ties and malformed records fail closed."""
    from .tool_contract import typed_equal
    collection, unique = extract_unique(value, path)
    if selection is None or not unique:
        return collection, unique
    if not isinstance(collection, list) or not 1 <= len(collection) <= 1024:
        return None, False
    candidates = []
    for item in collection:
        field, found = extract_unique(item, selection["field"])
        if not found:
            return None, False
        if selection["mode"] == "where":
            if typed_equal(field, selection["value"]):
                candidates.append(item)
        else:
            if type(field) not in (int, float) or (type(field) is float and not math.isfinite(field)):
                return None, False
            candidates.append((field, item))
    if selection["mode"] != "where" and candidates:
        choose = min if selection["mode"] == "min" else max
        extreme = choose(score for score, _ in candidates)
        candidates = [item for score, item in candidates if score == extreme]
    if len(candidates) != 1:
        return None, False
    return extract_unique(candidates[0], selection["project"])


def validate_reference(reference, declarations, contracts):
    """Validate an initial reference; scoped arguments never come from a call."""
    from .tool_contract import typed_equal
    if (not isinstance(reference, dict) or set(reference) - {"$binding", "source_arguments"}
            or not isinstance(reference.get("$binding"), str)):
        raise ValueError("Invalid binding reference")
    spec = declarations.get(reference["$binding"])
    if spec is None:
        raise ValueError("Unknown binding reference")
    if contracts[spec["target_tool"]].fields[spec["target_field"]].get("role") == "execution":
        raise ValueError("Executable parameters cannot use externally observed bindings")
    arguments = reference.get("source_arguments")
    if "source_arguments" not in reference:
        if spec.get("require_source_arguments", False):
            raise ValueError("Task-scoped source arguments required")
        return spec, None
    if not isinstance(arguments, dict):
        raise ValueError("Source arguments must be an object")
    contract = contracts[spec["source_tool"]]
    normalized = contract.normalize(arguments)
    if not typed_equal(arguments, normalized):
        raise ValueError("Specify every effective source argument without coercion")
    if any(key not in arguments or not typed_equal(arguments[key], value)
           for key, value in spec["source_arguments"].items()):
        raise ValueError("Task source scope exceeds the operator declaration")
    return spec, copy.deepcopy(arguments)


def complete_binding_scopes(rules, declarations, contracts):
    """Narrow an omitted scope to a unique, fully pinned INITIAL lookup rule.

    No runtime call, tool output or model history enters this compiler. If two
    different lookups are authorized, or any lookup is not fully pinned, the
    reference stays unresolved and ordinary semantic validation rejects it.
    """
    from .intent_validation import finite_domains
    from .tool_contract import typed_equal
    from . import symbolic
    result, records = copy.deepcopy(rules), []
    for index, rule in enumerate(result):
        if rule.get("decision") != "allow":
            continue
        def walk(pred, positive=True):
            for child in pred.get("args", []):
                walk(child, positive and pred.get("op") == "and")
            value = pred.get("value")
            if not (positive and pred.get("op") == "eq" and isinstance(value, dict)
                    and set(value) == {"$binding"} and isinstance(value["$binding"], str)):
                return
            spec = declarations.get(value["$binding"], {})
            if (not spec.get("require_source_arguments") or rule["tool"] != spec["target_tool"]
                    or pred["field"] != "payload." + spec["target_field"]):
                return
            source = contracts[spec["source_tool"]]
            candidates = []
            for source_rule in rules:
                if source_rule["tool"] != source.name or source_rule["decision"] != "allow":
                    continue
                domains = finite_domains(source_rule["predicate"])
                if domains is None or any(len(domains.get("payload." + f, [])) != 1 for f in source.fields):
                    return
                args = {f: domains["payload." + f][0] for f in source.fields}
                fields = symbolic.action_fields(source.name, args.get(source.target_field, source.name), args)
                for alias, name in source.aliases.items():
                    fields["payload." + alias] = args[name]
                if not symbolic.predicate_fields(source_rule["predicate"]) <= fields.keys():
                    return
                if not source._strict_holds(source_rule["predicate"], fields):
                    return
                if symbolic.check_rules(source.name, fields, rules)[0] != "allow":
                    return
                if not any(typed_equal(args, previous) for previous in candidates):
                    candidates.append(args)
            if len(candidates) != 1:
                return
            reference = {**value, "source_arguments": candidates[0]}
            try:
                validate_reference(reference, declarations, contracts)
            except (ValueError, TypeError):
                return
            pred["value"] = reference
            records.append({"rule_index": index, "binding": value["$binding"],
                            "source_arguments_hash": object_hash(candidates[0]),
                            "source": "unique_initial_allow_rule"})
        walk(rule["predicate"])
    return result, records


class RuntimeBindings:
    def __init__(self, declarations, contracts, *, task_id, clock=time.monotonic, rules=None):
        self.declarations = copy.deepcopy(declarations or {})
        self.contracts, self.task_id, self.clock = contracts, task_id, clock
        self.observations, self.used, self.last = {}, {}, []
        if not isinstance(self.declarations, dict) or len(self.declarations) > 128:
            raise ValueError("Invalid binding declarations")
        keys = {"target_tool", "target_field", "source_tool", "source_path", "source_arguments",
                "ttl_seconds", "max_uses", "reason"}
        for name, spec in self.declarations.items():
            if (not isinstance(name, str) or not name or not isinstance(spec, dict)
                    or not keys <= set(spec) or set(spec) - (keys | {"require_source_arguments", "selection", "derivation"})
                    or type(spec.get("require_source_arguments", False)) is not bool):
                raise ValueError("Binding declaration requires an exact reviewed schema")
            if "selection" in spec:
                validate_selection(spec["selection"])
            source, target = spec["source_tool"], spec["target_tool"]
            if source not in contracts or target not in contracts or spec["target_field"] not in contracts[target].fields:
                raise ValueError("Binding refers to unknown tool/parameter")
            if "derivation" in spec:
                from .binding_derivations import validate_derivation
                if not spec.get("require_source_arguments"):
                    raise ValueError("Derived bindings require task-scoped source arguments")
                validate_derivation(spec["derivation"], contracts[target], spec["target_field"])
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
        self.scopes = {name: (name, None) for name, spec in self.declarations.items()
                       if not spec.get("require_source_arguments", False)}
        def collect(value):
            if isinstance(value, dict):
                if "$binding" in value:
                    _, arguments = validate_reference(value, self.declarations, contracts)
                    name = value["$binding"]
                    key = self._key(name, arguments)
                    self.scopes[key] = (name, arguments)
                else:
                    for child in value.values():
                        collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)
        if rules is not None:
            collect(rules)

    @staticmethod
    def _key(name, arguments):
        return name if arguments is None else name + "@" + object_hash(arguments)

    def observe(self, tool, arguments, result, *, call_id, state_hash):
        """Trusted host only; call after successful authorization AND execution."""
        from .tool_contract import typed_equal
        for key, (name, scoped_args) in self.scopes.items():
            spec = self.declarations[name]
            if spec["source_tool"] != tool or any(
                    key not in arguments or not typed_equal(arguments[key], value)
                    for key, value in spec["source_arguments"].items()):
                continue
            if scoped_args is not None and not typed_equal(scoped_args, arguments):
                continue
            try:
                value, unique = extract_selected(json_value(result), spec["source_path"], spec.get("selection"))
                if not unique:
                    self.observations[key] = None
                    continue
                source_value_hash = object_hash(value)
                if "derivation" in spec:
                    from .binding_derivations import derive_value
                    value = derive_value(value, spec["derivation"],
                                         self.contracts[spec["target_tool"]], spec["target_field"])
                field = self.contracts[spec["target_tool"]].parameters.model_fields[spec["target_field"]]
                validated = TypeAdapter(field.rebuild_annotation()).validate_python(value, strict=True)
                if not typed_equal(json_value(validated), value):
                    raise ValueError("Binding would coerce a value")
            except (ValueError, TypeError):
                self.observations[key] = None
                continue
            record = {"value": copy.deepcopy(value), "call_id": call_id, "state_hash": state_hash,
                      "created": self.clock(), "source_arguments_hash": object_hash(arguments),
                      "source_value_hash": source_value_hash}
            # Identical read retries preserve the original provenance/lifetime.
            # A different argument, value or environment remains ambiguous.
            if key in self.observations:
                previous = self.observations[key]
                if not (previous and previous["state_hash"] == state_hash
                        and previous["source_arguments_hash"] == object_hash(arguments)
                        and previous["source_value_hash"] == source_value_hash
                        and typed_equal(previous["value"], value)):
                    self.observations[key] = None
            else:
                self.observations[key] = record

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
                try:
                    spec, arguments = validate_reference(value, self.declarations, self.contracts)
                except (ValueError, TypeError):
                    return False
                key = self._key(name, arguments)
                record = self.observations.get(key)
                if (not positive or pred.get("op") != "eq"
                        or rule.get("tool") != spec["target_tool"]
                        or pred.get("field") != "payload." + spec["target_field"] or not record
                        or record["state_hash"] != state_hash
                        or self.clock() - record["created"] >= spec["ttl_seconds"]
                        or self.used.get(key, 0) >= spec["max_uses"]):
                    return False
                pred["value"] = copy.deepcopy(record["value"])
                # eq-null does not count as finite coverage in the core DSL.
                if pred["value"] is None:
                    pred.update(op="in", value=[None])
                records.append({"binding": name, "task_id": self.task_id,
                                "scope_key": key,
                                "declaration_hash": object_hash(spec),
                                "source_call_id": record["call_id"], "state_hash": state_hash,
                                "source_value_hash": record["source_value_hash"],
                                "value_hash": object_hash(record["value"]), "target_tool": rule["tool"],
                                "target_field": spec["target_field"]})
                return True
            if walk(rule.get("predicate")):
                result.append(rule)
                self.last.extend(records)
        return result

    def consume(self, tool):
        # Conservatively consume every resolved binding for this target tool.
        for name in {r["scope_key"] for r in self.last if r["target_tool"] == tool}:
            self.used[name] = self.used.get(name, 0) + 1

    def diagnostics(self):
        return {"declared": sorted(self.declarations), "observed": sorted(self.observations),
                "invalid_or_ambiguous": sorted(k for k, v in self.observations.items() if v is None),
                "used": dict(self.used)}
