"""Trusted simulator map envelopes; never an operating-system path grant."""
import copy
from policy.engine import PolicyEngine
from policy.resource_provenance import at


def validate_virtual_resource(spec, contract):
    declaration = spec.get('virtual_resource')
    if declaration is None:
        return
    if (not spec.get('schema_hash') or not isinstance(declaration, dict)
            or set(declaration) != {'parameter', 'collection', 'reason'}
            or declaration['parameter'] not in contract.fields
            or contract.fields[declaration['parameter']]['role'] != 'resource'
            or not isinstance(declaration['collection'], list) or not 1 <= len(declaration['collection']) <= 8
            or any(not isinstance(p, str) or not p for p in declaration['collection'])
            or not isinstance(declaration['reason'], str) or not declaration['reason'].strip()
            or spec.get('semantic_action', {}).get('operation') != 'read'
            or spec['capability'].get('filesystem_read') or spec['capability'].get('filesystem_write')
            or any(spec['capability'].get(k) == 'allowed' for k in ('process','persistence','network_egress','external_share'))):
        raise ValueError('Virtual read envelope requires an isolated read-only simulator map')


class SimulationPolicyEngine(PolicyEngine):
    def __init__(self, *args, virtual_resources, snapshot, **kwargs):
        super().__init__(*args, **kwargs)
        self.virtual_resources = copy.deepcopy(virtual_resources)
        self.snapshot = snapshot

    def _path_in_envelope(self, policy, capability, action):
        declaration = self.virtual_resources.get(action.type)
        if declaration is None:
            return super()._path_in_envelope(policy, capability, action)
        try:
            collection = at(self.snapshot(), declaration['collection'])
            key = action.payload.get(declaration['parameter'])
            valid = (isinstance(collection, dict) and isinstance(key, str)
                     and key == action.target and key in collection)
            return valid, 'simulator_map', declaration['collection']
        except (ValueError, TypeError):
            return False, 'simulator_map', declaration['collection']
