"""Host provenance admission and bounded read scopes, never task permission."""
import copy
import re

from attestation.hashing import object_hash
from .resource_provenance import at


def validate_audit_secrets(spec, contract):
    fields = spec.get('audit_secret_parameters', [])
    if (not isinstance(fields, list) or len(fields) > 32 or any(not isinstance(x,str) for x in fields)
            or len(fields) != len(set(fields)) or any(x not in contract.fields for x in fields)
            or fields and not spec.get('schema_hash')):
        raise ValueError('Audit secret parameters require known fields and a pinned schema')


def argument_effect_admission(spec, proof, *, scoped_contract=False):
    """Distinguish missing facts from an unreviewed tool effect boundary.

    Complete literal witnesses do not prove that a tool has no implicit reads,
    disclosures or execution effects. Only a trusted adapter declaration can
    establish applicability, and an independent exact-call review still follows.
    """
    eligible = bool(spec.get('schema_hash')) and bool(
        scoped_contract or spec.get('parameter_evidence')
        or spec.get('review_data_use', {}).get('flow_review')
        or spec.get('dataflow_mode') == 'initial_arguments'
        or spec.get('dataflow_mode') in {'bound_resource_update', 'bound_resource_arguments'}
        and proof.get('resource_bindings'))
    supported = proof.get('complete') is True or proof.get('review_ready') is True
    return {'eligible': eligible, 'sources_supported': supported,
            'admissible': eligible and supported,
            'failure': None if eligible and supported else
                       'source_evidence' if not supported else 'effect_scope_undeclared',
            'missing_fields': list(proof.get('missing_fields', [])),
            'task_authorized': False}


def validate_resolution_read(spec, contract, adapter):
    declaration = spec.get('resolution_read')
    if declaration is None:
        return
    def path(value):
        return (isinstance(value, list) and 1 <= len(value) <= 12 and
                all(isinstance(x, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', x) for x in value))
    if (not spec.get('schema_hash') or adapter is None or not isinstance(declaration, dict)
            or set(declaration) != {'namespace', 'collections', 'reason'}
            or not path(declaration['namespace']) or not isinstance(declaration['collections'], list)
            or not 1 <= len(declaration['collections']) <= 8
            or any(not path(p) for p in declaration['collections'])
            or not isinstance(declaration['reason'], str) or not declaration['reason'].strip()
            or adapter.declaration['operation'] not in {'read', 'list', 'search'}
            or not set(adapter.upper_bound) <= {'read', 'filesystem_read'}
            or any(v['role'] == 'execution' for v in contract.fields.values())):
        raise ValueError('Resolution reads require pinned, independently bounded native read effects')


def resolution_read_context(spec, state):
    declaration = spec.get('resolution_read')
    if not declaration:
        return None
    try:
        namespace = at(state, declaration['namespace'])
        if not isinstance(namespace, str) or not namespace:
            return None
        scopes = []
        for path in declaration['collections']:
            collection = at(state, path)
            if not isinstance(collection, (dict, list)) or len(collection) > 2048:
                return None
            scopes.append({'path': copy.deepcopy(path), 'snapshot_hash': object_hash(collection)})
    except (TypeError, ValueError):
        return None
    return {'kind': 'READ_FOR_RESOLUTION', 'native_scope_verified': True,
            'namespace_hash': object_hash(namespace), 'collections': scopes,
            'necessity_proven': False, 'task_authorized': False,
            'use_of_results': 'requires_separate_authorization_for_every_sensitive_write',
            'scope_hash': object_hash([namespace, scopes])}
