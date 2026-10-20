"""Trusted, schema-bound parameter contracts shared by tool adapters.

The schema describes structure; only operator declarations describe whether a
default has no additional effect. Neither model arguments nor tool results can
extend the contract. Unknown parameter semantics default to intent-bound.
"""
import copy
import json
from pydantic import TypeAdapter
from attestation.hashing import object_hash
from . import symbolic
from .symbolic import predicate_fields


def typed_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(typed_equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(typed_equal(a, b) for a, b in zip(left, right))
    return left == right


class ToolContract:
    def __init__(self, name, parameters, *, semantics=None, schema_hash=None,
                 legacy_empty_values=None, target_field=None, aliases=None, roles=None):
        self.name, self.parameters = name, parameters
        self.schema = parameters.model_json_schema()
        self.schema_hash = object_hash(self.schema)
        if schema_hash is not None and schema_hash != self.schema_hash:
            raise ValueError(f"Tool schema changed: {name}; review its parameter contract")
        semantics = copy.deepcopy({} if semantics is None else semantics)
        if not isinstance(semantics, dict):
            raise ValueError("parameter_semantics must be an object")
        if semantics and schema_hash is None:
            raise ValueError("Parameter semantics require a reviewed schema hash")
        if set(semantics) - set(parameters.model_fields):
            raise ValueError("Parameter semantics name an unknown field")
        self.target_field, self.aliases = target_field, copy.deepcopy(aliases or {})
        if target_field is not None and target_field not in parameters.model_fields:
            raise ValueError("Unknown target parameter")
        if any(k in parameters.model_fields or v not in parameters.model_fields for k, v in self.aliases.items()):
            raise ValueError("Invalid parameter alias")
        self.empty_values = copy.deepcopy({} if legacy_empty_values is None else legacy_empty_values)
        if not isinstance(self.empty_values, dict) or set(self.empty_values) - set(parameters.model_fields):
            raise ValueError("Invalid legacy empty-value declaration")
        for field_name, values in self.empty_values.items():
            field = parameters.model_fields[field_name]
            if field.is_required() or field.default_factory is not None or not isinstance(values, list) or not values:
                raise ValueError("Legacy empty values require a static optional field")
            for value in values:
                if not (value is None or type(value) is str and value == "" or type(value) is list and not value):
                    raise ValueError("Legacy declarations only permit empty values")
                if not typed_equal(value, TypeAdapter(field.rebuild_annotation()).validate_python(value, strict=True)):
                    raise ValueError("Legacy empty value needs coercion")
            if not any(typed_equal(field.default, value) for value in values):
                raise ValueError("Legacy default is not an approved empty value")
        self.fields = {}
        roles = copy.deepcopy({} if roles is None else roles)
        if not isinstance(roles, dict) or set(roles) - set(parameters.model_fields) or (roles and schema_hash is None):
            raise ValueError("Parameter roles require known fields and a reviewed schema hash")
        for field_name, declaration in roles.items():
            if (not isinstance(declaration, dict) or set(declaration) != {"role", "reason"}
                    or declaration["role"] not in {"control", "resource", "destination", "content", "execution"}
                    or not isinstance(declaration["reason"], str) or not declaration["reason"].strip()
                    or (field_name == target_field and declaration["role"] == "content")):
                raise ValueError("Invalid reviewed parameter role")
        self.roles = roles
        for field_name, field in parameters.model_fields.items():
            declaration = semantics.get(field_name, {"mode": "intent_bound"})
            if not isinstance(declaration, dict):
                raise ValueError("Invalid parameter semantics")
            mode = declaration.get("mode")
            if mode == "intent_bound":
                if set(declaration) != {"mode"}:
                    raise ValueError("intent_bound does not grant defaults")
            elif mode == "no_additional_effect":
                if set(declaration) != {"mode", "values", "reason"}:
                    raise ValueError("No-effect semantics require values and a review reason")
                if not isinstance(declaration["reason"], str) or not declaration["reason"].strip():
                    raise ValueError("Missing operator review reason")
                if field.is_required() or field.default_factory is not None:
                    raise ValueError("No-effect semantics require a static optional default")
                values = declaration["values"]
                if not isinstance(values, list) or not values or len(values) > 32:
                    raise ValueError("No-effect semantics require 1..32 explicit values")
                adapter = TypeAdapter(field.rebuild_annotation())
                for value in values:
                    json.dumps(value, allow_nan=False)
                    if not typed_equal(value, adapter.validate_python(value, strict=True)):
                        raise ValueError("No-effect values must not require coercion")
                if not any(typed_equal(field.default, v) for v in values):
                    raise ValueError("Default not covered by reviewed no-effect values")
                if field_name in self.empty_values and not typed_equal(self.empty_values[field_name], values):
                    raise ValueError("Conflicting legacy and new parameter semantics")
                self.empty_values[field_name] = copy.deepcopy(values)
            else:
                raise ValueError("Unsupported parameter semantics mode")
            record = {"required": field.is_required(), "mode": mode}
            record["role"] = roles.get(field_name, {}).get("role", "control")
            if not field.is_required():
                if field.default_factory is not None:
                    raise ValueError("Dynamic defaults need a dedicated trusted adapter")
                record["default"] = copy.deepcopy(field.default)
            if field_name in self.empty_values:
                record["mode"] = "no_additional_effect"
                record["values"] = copy.deepcopy(self.empty_values[field_name])
            self.fields[field_name] = record
        self.fingerprint = object_hash(self.report())

    def report(self):
        return {"tool": self.name, "schema_hash": self.schema_hash, "parameters": copy.deepcopy(self.fields),
                "target_field": self.target_field, "aliases": copy.deepcopy(self.aliases)}

    def normalize(self, arguments):
        if object_hash(self.parameters.model_json_schema()) != self.schema_hash:
            raise ValueError("Tool schema changed during the session")
        frozen = json.loads(json.dumps(arguments, allow_nan=False))
        if not isinstance(frozen, dict) or set(frozen) - set(self.fields):
            raise ValueError("Unknown tool arguments")
        return self.parameters.model_validate(frozen).model_dump(mode="json")

    def rule_coverage(self, rules):
        """Diagnostic only: discovery/coverage is never an execution grant."""
        rows = []
        for index, rule in enumerate(rules):
            if rule.get("tool") != self.name or rule.get("decision") != "allow":
                continue
            pred = rule.get("predicate", {})
            bounded = symbolic.constrained_fields(pred)
            if self.target_field and "target" in bounded:
                bounded.add("payload." + self.target_field)
            for alias, field in self.aliases.items():
                if "payload." + alias in bounded:
                    bounded.add("payload." + field)
            rows.append({"rule_index": index, "unbounded_fields": sorted(
                {"payload." + field for field in self.fields} - bounded),
                "has_runtime_reference": '"$binding"' in json.dumps(pred)})
        return {"tool": self.name, "has_task_allow_rule": bool(rows), "rules": rows}

    def rule_coverage(self, rules):
        """Diagnostic only: discovery/coverage is never an execution grant."""
        rows = []
        for index, rule in enumerate(rules):
            if rule.get("tool") != self.name or rule.get("decision") != "allow":
                continue
            pred = rule.get("predicate", {})
            bounded = symbolic.constrained_fields(pred)
            if self.target_field and "target" in bounded:
                bounded.add("payload." + self.target_field)
            for alias, field in self.aliases.items():
                if "payload." + alias in bounded:
                    bounded.add("payload." + field)
            rows.append({"rule_index": index, "unbounded_fields": sorted(
                {"payload." + field for field in self.fields} - bounded),
                "has_runtime_reference": '"$binding"' in json.dumps(pred)})
        return {"tool": self.name, "has_task_allow_rule": bool(rows), "rules": rows}

    def complete_rules(self, rules):
        # Compatibility compiler only emits existing DSL predicates. It has no
        # dependency on AgentDojo runtime or any tool implementation.
        completed = complete_rules(rules, {"tools": {self.name: {"optional_empty_values": self.empty_values}}})
        # Explicit intent null is a finite value even when it is not an
        # operator-declared no-effect default. Never infer such intent.
        def normalize_null(pred):
            field = pred.get("field", "")
            name = field.removeprefix("payload.")
            if (pred.get("op") == "eq" and "value" in pred and pred["value"] is None
                    and field == "payload." + name and name in self.fields):
                try:
                    TypeAdapter(self.parameters.model_fields[name].rebuild_annotation()).validate_python(None, strict=True)
                except ValueError:
                    pass
                else:
                    pred["op"], pred["value"] = "in", [None]
            for child in pred.get("args", []):
                if isinstance(child, dict):
                    normalize_null(child)
        for rule in completed:
            if rule.get("tool") == self.name and rule.get("decision") == "allow" and isinstance(rule.get("predicate"), dict):
                normalize_null(rule["predicate"])
        return completed

    def check(self, action, rules, capability):
        """Check ALL effective arguments against one matching intent rule.

        Keep deny precedence and do not merge independent rules into a Cartesian
        product. Null bounds are explicit finite sets; loose OR branches do not
        count as coverage. This gate never overrides a core denial.
        """
        fields = symbolic.action_fields(action.type, action.target, action.payload)
        verdict, matched = symbolic.check_rules(action.type, fields, symbolic.validate_rules(rules, capability))
        if verdict != "allow" or not matched or matched.get("tool") != self.name:
            return {"verdict": "CONFIRM", "rule": "contract.intent",
                    "reason": "No matching tool-specific intent authorization"}
        bounded = symbolic.constrained_fields(matched["predicate"])
        if (self.target_field and "target" in bounded and self.target_field in action.payload
                and typed_equal(action.target, action.payload[self.target_field])):
            bounded.add("payload." + self.target_field)
        for alias, source in self.aliases.items():
            if ("payload." + alias in bounded and alias in action.payload and source in action.payload
                    and typed_equal(action.payload[alias], action.payload[source])):
                bounded.add("payload." + source)
        missing = {"payload." + name for name in self.fields} - bounded
        if missing:
            return {"verdict": "CONFIRM", "rule": "contract.coverage",
                    "fields": sorted(missing),
                    "reason": "Effective arguments not bounded: " + str(sorted(missing))}
        if not self._strict_holds(matched["predicate"], fields):
            return {"verdict": "BLOCK", "rule": "contract.value_type",
                    "reason": "Argument values do not exactly match their intent bounds"}
        return None

    @classmethod
    def _strict_holds(cls, pred, fields):
        op = pred.get("op")
        if op == "and":
            return all(cls._strict_holds(p, fields) for p in pred["args"])
        if op == "or":
            return any(cls._strict_holds(p, fields) for p in pred["args"])
        if op == "not":
            return not cls._strict_holds(pred["args"][0], fields)
        if op in ("eq", "in"):
            field = pred.get("field")
            if field not in fields:
                return False
            values = [pred.get("value")] if op == "eq" else pred.get("value", [])
            return any(typed_equal(fields[field], value) for value in values)
        return symbolic.predicate_holds(pred, fields)


def complete_rules(rules, manifest):
    """Conjoin finite empty bounds only to existing tool-specific allow rules.

    No observed action, model history or benchmark goal influences this step.
    Existing explicit field predicates (including OR/NOT) are not overridden.
    Denies and wildcard rules remain unchanged.
    """
    result = copy.deepcopy(rules)
    for rule in result:
        spec = manifest["tools"].get(rule.get("tool"))
        if not spec or rule.get("decision") != "allow":
            continue
        pred = rule.get("predicate")
        if not isinstance(pred, dict):
            continue
        declarations = spec.get("optional_empty_values", {})
        # eq null is not counted as bounded by the core DSL. Singleton in
        # expresses the same value set and is already supported by the core.
        def normalize(node):
            field = node.get("field", "")
            name = field.removeprefix("payload.")
            if (node.get("op") == "eq" and "value" in node and node["value"] is None
                    and field == "payload." + name and name in declarations
                    and None in declarations[name]):
                node["op"], node["value"] = "in", [None]
            for child in node.get("args", []):
                if isinstance(child, dict):
                    normalize(child)
        normalize(pred)
        mentioned = predicate_fields(pred)
        extra = [{"op": "in", "field": "payload." + name, "value": copy.deepcopy(values)}
                 for name, values in declarations.items() if "payload." + name not in mentioned]
        if extra:
            rule["predicate"] = {"op": "and", "args": [pred, *extra]}
    return result
