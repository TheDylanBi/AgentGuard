"""Operator assertions, never inferred from benchmark labels or tool prose.

Pins authenticate reviewed artifacts, not semantic correctness. ASB cannot
enforce real resource/data-flow scopes; version 2 binds the configured simulator.
"""
import copy
import base64
import hashlib
import json
import re
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from attestation.hashing import object_hash
from policy.semantic_action import EFFECTS, OPERATIONS


def _text(value):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 2048


def _pin(value):
    return isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None


def _texts(value):
    return (isinstance(value, list) and len(value) <= 32 and
            all(_text(x) for x in value) and len(set(value)) == len(value))


def _object(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            raise ValueError('Duplicate tool contract key')
        value[key] = child
    return value


def implementation_identity(tool):
    """Hash static ASB instance fields, including configured return behavior.

    Contents never go to review. Stateful real tools need another adapter that
    separates immutable configuration from mutable execution state.
    """
    return {'entrypoint': type(tool).__module__ + '.' + type(tool).__qualname__ + '.run',
            'configuration_hash': object_hash(vars(tool))}


class ToolContracts:
    def __init__(self, path=None, signature_path=None, public_key_path=None):
        self.entries = {}
        self.version = None
        self.fingerprint = None
        self.signature_verified = False
        self.signer_public_key_hash = None
        if bool(signature_path) != bool(public_key_path):
            raise ValueError('Tool contract signature and public key must be supplied together')
        if path is None:
            if signature_path or public_key_path:
                raise ValueError('Cannot verify a missing tool contract')
            return
        data = json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=_object)
        if signature_path:
            signature = Path(signature_path).read_text(encoding='ascii').strip()
            if not signature.startswith('ed25519:'):
                raise ValueError('Invalid tool contract signature format')
            try:
                public_bytes = Path(public_key_path).read_bytes()
                key = serialization.load_pem_public_key(public_bytes)
                raw = base64.b64decode(signature.split(':', 1)[1], validate=True)
                canonical = json.dumps(data, sort_keys=True, separators=(',', ':')).encode('utf-8')
                key.verify(raw, canonical)
            except Exception:
                raise ValueError('Tool contract signature verification failed') from None
            self.signature_verified = True
            self.signer_public_key_hash = 'sha256:' + hashlib.sha256(public_bytes).hexdigest()
        if (not isinstance(data, dict) or set(data) != {'version', 'tools'} or
                type(data['version']) is not int or data['version'] not in {1, 2} or not isinstance(data['tools'], dict)):
            raise ValueError('Invalid operator tool contracts')
        self.version = data['version']
        for name, entry in data['tools'].items():
            common = {'issuer', 'catalog_hash', 'runtime_hash', 'operation', 'effects'}
            extra = {'provenance', 'implementation', 'capability'} if self.version == 2 else set()
            if (not _text(name) or not isinstance(entry, dict) or set(entry) != common | extra or
                    not _text(entry['issuer']) or not isinstance(entry['operation'], str) or
                    entry['operation'] not in OPERATIONS or not _texts(entry['effects']) or
                    not set(entry['effects']) <= EFFECTS or
                    any(not _pin(entry[key]) for key in ('catalog_hash', 'runtime_hash'))):
                raise ValueError('Invalid operator capability declaration')
            if self.version == 2:
                provenance, impl, cap = (entry[x] for x in ('provenance', 'implementation', 'capability'))
                if (not isinstance(provenance, dict) or set(provenance) != {'source', 'review_reference'} or
                        not all(_text(x) for x in provenance.values()) or
                        not isinstance(impl, dict) or set(impl) != {'version', 'entrypoint', 'configuration_hash'} or
                        not _text(impl['version']) or not _text(impl['entrypoint']) or
                        not _pin(impl['configuration_hash']) or
                        not isinstance(cap, dict) or
                        set(cap) != {'purpose', 'resource_type', 'reads', 'writes', 'data_flows'} or
                        not _text(cap['purpose']) or not _text(cap['resource_type']) or
                        not _texts(cap['reads']) or not _texts(cap['writes']) or
                        not isinstance(cap['data_flows'], list) or len(cap['data_flows']) > 32 or
                        any(not isinstance(flow, dict) or set(flow) != {'source', 'destination'} or
                            not all(_text(x) for x in flow.values()) for flow in cap['data_flows'])):
                    raise ValueError('Invalid complete operator contract')
                # Operation and effects are independent dimensions. A lookup
                # may need a network request, and a compound read may mutate
                # state. Preserve those effects for authorization; never erase
                # them or call them safe merely because operation == "read".
                writes = {'create', 'update', 'delete', 'mark_read', 'filesystem_write',
                          'persistence', 'financial_transfer', 'physical_action'}
                if cap['writes'] and not set(entry['effects']) & writes:
                    raise ValueError('Write scope requires a declared write effect')
                if set(entry['effects']) & writes and not cap['writes']:
                    raise ValueError('Write effects require explicit write scope')
                if set(entry['effects']) & {'network_egress', 'external_communication', 'share'} and not cap['data_flows']:
                    raise ValueError('Communication effects require explicit data flows')
            self.entries[name] = copy.deepcopy(entry)
        self.fingerprint = object_hash(data)

    def snapshot(self):
        return {'version': self.version, 'tools': copy.deepcopy(self.entries)}

    def coverage(self, catalogs, runtime_hash):
        """Preflight selected catalogs without deriving trust from benchmark labels."""
        selected = {}
        for catalog in catalogs:
            for name, spec in catalog.items():
                if name in selected and selected[name] != spec:
                    raise ValueError('Conflicting catalog declarations for one tool')
                selected[name] = copy.deepcopy(spec)
        rows = []
        for name, spec in sorted(selected.items()):
            assurance = self.resolve(name, spec, runtime_hash)
            rows.append({'tool': name,
                'declared': name in self.entries,
                'catalog_claim_verified': assurance['catalog_claim_verified'],
                'contract_complete': assurance['contract_complete'],
                'contract_hash': assurance.get('contract_hash')})
        return {'selected_tool_count': len(rows),
            'declared_count': sum(row['declared'] for row in rows),
            'complete_count': sum(row['contract_complete'] for row in rows),
            'missing_tools': [row['tool'] for row in rows if not row['declared']],
            'incomplete_tools': [row['tool'] for row in rows if row['declared'] and not row['contract_complete']],
            'unused_declarations': sorted(set(self.entries) - set(selected)),
            'signature_verified': self.signature_verified,
            'signer_public_key_hash': self.signer_public_key_hash,
            'tools': rows,
            'meaning': 'Coverage of selected tool declarations; neither coverage nor signature grants task permission.'}

    def resolve(self, tool, spec, runtime_hash, instance=None):
        entry = self.entries.get(tool)
        if entry is None:
            return {'catalog_claim_verified': False, 'contract_complete': False,
                    'instance_verified': False, 'business_effects': 'unknown',
                    'meaning': 'catalog prose is untrusted; registration is not task permission'}
        if entry['catalog_hash'] != object_hash({'tool': tool, 'description': spec['description']}) or entry['runtime_hash'] != runtime_hash:
            raise ValueError('Operator tool contract pin mismatch')
        complete = self.version == 2
        if complete and instance is not None:
            identity = implementation_identity(instance)
            if any(identity[k] != entry['implementation'][k] for k in identity):
                raise ValueError('Operator implementation or configuration pin mismatch')
        result = {'catalog_claim_verified': True, 'contract_complete': complete,
                'instance_verified': complete and instance is not None, 'issuer': entry['issuer'],
                'operation': entry['operation'], 'effect_upper_bound': copy.deepcopy(entry['effects']),
                'contract_hash': object_hash(entry),
                'meaning': 'operator declaration; not task permission or proof of implementation correctness'}
        if complete:
            result.update({key: copy.deepcopy(entry[key]) for key in ('provenance', 'implementation', 'capability')})
            result['scope_enforcement'] = 'asserted for fixed-string simulation; no real resource/data-flow enforcement'
        return result
