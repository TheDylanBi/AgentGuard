"""Operator-declared, schema-bound action normalization. No LLM planning.

The result describes declared effects and capability upper bounds before
execution, not an observation of what a tool actually did. Declarations remain
part of the trusted adapter; a schema hash does not verify tool implementation.
"""
import copy
import re

from attestation.hashing import object_hash

OPERATIONS = {"read", "list", "search", "create", "update", "append", "cancel", "delete", "send", "share", "execute"}
EFFECTS = {"read", "create", "update", "delete", "mark_read", "share", "external_communication",
           "filesystem_read", "filesystem_write", "network_egress", "process_execution",
           "credential_access", "persistence", "financial_transfer", "physical_action"}
EFFECT_TYPES = {"data_mutation": "update", "external_communication": "external_communication",
    "filesystem_read": "filesystem_read", "filesystem_write": "filesystem_write",
    "network_navigation": "network_egress", "arbitrary_process_execution": "process_execution",
    "credential_access": "credential_access", "financial_transfer": "financial_transfer",
    "share": "share", "physical_action": "physical_action"}


class SemanticAdapter:
    def __init__(self, contract, declaration, capability):
        required = {"version", "operation", "resource_type", "fields", "effects", "reason"}
        if (not isinstance(declaration, dict) or not required <= set(declaration)
                or set(declaration) - (required | {'parameter_effects', 'inseparable_read_effects'})
                or type(declaration["version"]) is not int or declaration["version"] != 1
                or not isinstance(declaration["operation"], str) or declaration["operation"] not in OPERATIONS):
            raise ValueError("Invalid semantic action declaration")
        if (not isinstance(declaration["resource_type"], str)
                or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", declaration["resource_type"])
                or not isinstance(declaration["reason"], str) or not declaration["reason"].strip()):
            raise ValueError("Semantic declaration requires resource type and review reason")
        mapping = declaration["fields"]
        if (not isinstance(mapping, dict) or set(mapping) != set(contract.fields)
                or any(not isinstance(slot, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", slot)
                       for slot in mapping.values()) or len(set(mapping.values())) != len(mapping)):
            raise ValueError("Semantic mapping must uniquely cover every effective parameter")
        effects = declaration["effects"]
        read_effects = declaration.get('inseparable_read_effects', [])
        if (not isinstance(read_effects, list) or any(x != 'mark_read' for x in read_effects)
                or len(read_effects) != len(set(read_effects))
                or read_effects and (declaration['operation'] not in {'read', 'list'}
                                    or not {'read', *read_effects} <= set(effects))):
            raise ValueError('Invalid inseparable read effect declaration')
        field_effects = declaration.get('parameter_effects', {})
        if (not isinstance(field_effects, dict) or set(field_effects)-set(mapping)
                or any(not isinstance(effect, str) or effect not in {'replace', 'append', 'add_members', 'remove_members'}
                       for effect in field_effects.values())):
            raise ValueError('Invalid schema-bound parameter effect')
        def has_type(schema, expected):
            return schema.get('type') == expected or any(has_type(s, expected) for s in schema.get('anyOf', []))
        for field, effect in field_effects.items():
            schema = contract.schema['properties'][field]
            if effect in {'add_members', 'remove_members'} and not has_type(schema, 'array'):
                raise ValueError('Membership effects require an array parameter')
            if effect == 'append' and not (has_type(schema, 'array') or has_type(schema, 'string')):
                raise ValueError('Append effect requires a string or array parameter')
        if (not isinstance(effects, list) or not effects or any(not isinstance(x, str) or x not in EFFECTS for x in effects)
                or len(effects) != len(set(effects))):
            raise ValueError("Invalid declared semantic effects")
        caps = copy.deepcopy(capability)
        if declaration["operation"] in {"create", "update", "append", "cancel", "delete"} or set(effects) & {"create", "update", "delete", "mark_read"}:
            if caps.get("persistence") != "allowed" and not caps.get("filesystem_write"):
                raise ValueError("Mutation semantics exceed declared capability")
        for effect, flag in {"external_communication": "external_share", "share": "external_share",
                             "financial_transfer":"financial_transfer",
                             "process_execution": "process", "network_egress": "network_egress",
                             "credential_access": "credential_access"}.items():
            if effect in effects and caps.get(flag) != "allowed":
                raise ValueError("Semantic effect exceeds capability: " + effect)
        self.contract = contract
        self.declaration, self.capability = copy.deepcopy(declaration), caps
        self.mapping = copy.deepcopy(mapping)
        self.reverse = {slot: field for field, slot in mapping.items()}
        upper = set(effects)
        kind = caps.get("effect_type")
        if kind:
            if kind not in EFFECT_TYPES:
                raise ValueError("Unknown capability effect requires a reviewed adapter")
            upper.add(EFFECT_TYPES[kind])
        for flag, effect in {"process": "process_execution", "network": "network_egress",
                "network_egress": "network_egress", "external_share": "external_communication",
                "credential": "credential_access", "credential_access": "credential_access",
                "persistence": "persistence", "financial_transfer":"financial_transfer"}.items():
            if caps.get(flag) == "allowed":
                upper.add(effect)
        for field in ("filesystem_read", "filesystem_write"):
            if caps.get(field):
                upper.add(field)
        self.upper_bound = sorted(upper)
        self.fingerprint = object_hash({"schema": contract.schema_hash,
            "contract": contract.fingerprint, "declaration": declaration, "capability": caps})

    def normalize(self, arguments, *, resolved_destinations=None):
        if set(arguments) != set(self.mapping):
            raise ValueError("Semantic action requires complete normalized arguments")
        result = {"version": 1, "operation": self.declaration["operation"],
                "resource_type": self.declaration["resource_type"],
                "parameters": {slot: copy.deepcopy(arguments[field]) for field, slot in sorted(self.mapping.items(), key=lambda item: item[1])},
                "parameter_roles": {slot: self.contract.fields[field]["role"]
                                    for field, slot in sorted(self.mapping.items(), key=lambda item: item[1])},
                "effect_upper_bound": self.upper_bound[:],
                "data_sources": sorted(self.capability.get("sources") or []),
                "resolved_destinations": copy.deepcopy(resolved_destinations)}
        if self.declaration.get('parameter_effects'):
            result['parameter_effects'] = {self.mapping[field]: effect
                for field, effect in self.declaration['parameter_effects'].items()}
        if self.declaration.get('inseparable_read_effects'):
            result['inseparable_read_effects'] = self.declaration['inseparable_read_effects'][:]
        return result

    def execution_boundary(self):
        return ("process_execution" in self.upper_bound or
                any(field["role"] == "execution" for field in self.contract.fields.values()))
