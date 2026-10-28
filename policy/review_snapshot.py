"""Exact review inputs for offline analysis; replay NEVER executes a tool.

Snapshots contain task data but no service credentials. Hashes detect accidental
change, not malicious re-signing; only host-created snapshots are authoritative.
"""
import copy
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path

from attestation.hashing import object_hash

_SINK = ContextVar('review_input_sink', default=None)
MAX_SNAPSHOT_BYTES = 600_000
OPTION_DEFAULTS = {'output_format': 'text', 'compact_json': 'false', 'max_tokens': None,
                   'thinking': None, 'reasoning_effort': None, 'thinking_mode': None}


class ReviewSnapshotError(ValueError):
    def __init__(self, code):
        self.diagnostic = {'stage': 'review_snapshot', 'status': code}
        super().__init__(code)


def model_identity():
    from .intent_anchor import _llm_config
    config = _llm_config()
    return {'model': config['model'], 'endpoint_hash': object_hash(config['base_url'].rstrip('/'))}


def runtime_identity():
    root = Path(__file__).parent
    return {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in
            ('call_review.py', 'review_snapshot.py', 'intent_anchor.py', 'intent_output.py')}


def effective_options(options):
    """Freeze fallbacks so a later environment cannot silently change the body."""
    result = dict(options)
    for key, env in (('output_format', 'OUTPUT_FORMAT'), ('compact_json', 'COMPACT_JSON'),
                     ('max_tokens', 'MAX_TOKENS'), ('thinking', 'ENABLE_THINKING')):
        result.setdefault(key, os.environ.get('ICB_INTENT_LLM_'+env, OPTION_DEFAULTS[key]))
    for key in ('reasoning_effort', 'thinking_mode'):
        result.setdefault(key, None)
    return result


@contextmanager
def capture_review_inputs(sink):
    token = _SINK.set(sink)
    try:
        yield
    finally:
        _SINK.reset(token)


def emit_review_input(packet, system, user, schema, options, timeout_seconds):
    sink = _SINK.get()
    if sink is None:
        return
    value = {'version': 1, 'kind': 'review_input', 'capture_stage': 'prepared_before_transport',
             'packet': copy.deepcopy(packet),
             'request': {'system': system, 'user': user, 'schema': copy.deepcopy(schema),
                         'options': copy.deepcopy(options), 'temperature': 0.0},
             'model_identity': model_identity(), 'runtime_identity': runtime_identity(),
             'client_budget': {'timeout_seconds': timeout_seconds,
                               'transport_timeout_setting': os.environ.get('ICB_INTENT_LLM_TIMEOUT_SECONDS', '30')}}
    value['snapshot_hash'] = object_hash(value)
    if len(json.dumps(value, ensure_ascii=False).encode('utf-8')) > MAX_SNAPSHOT_BYTES:
        raise ReviewSnapshotError('snapshot_size_limit')
    sink(copy.deepcopy(value))


def validate_snapshot(snapshot):
    fields = {'version', 'kind', 'capture_stage', 'packet', 'request', 'model_identity', 'runtime_identity', 'client_budget', 'snapshot_hash'}
    if (not isinstance(snapshot, dict) or set(snapshot) != fields or
            type(snapshot['version']) is not int or snapshot['version'] != 1 or snapshot['kind'] != 'review_input' or
            snapshot['capture_stage'] != 'prepared_before_transport'):
        raise ReviewSnapshotError('invalid_snapshot_shape')
    unsigned = {k: v for k, v in snapshot.items() if k != 'snapshot_hash'}
    if object_hash(unsigned) != snapshot['snapshot_hash']:
        raise ReviewSnapshotError('snapshot_hash_mismatch')
    if snapshot['model_identity'] != model_identity():
        raise ReviewSnapshotError('review_model_or_endpoint_changed')
    if snapshot['runtime_identity'] != runtime_identity():
        raise ReviewSnapshotError('review_runtime_changed')
    request = snapshot['request']
    if (not isinstance(request, dict) or set(request) != {'system', 'user', 'schema', 'options', 'temperature'} or
            not isinstance(request['system'], str) or not isinstance(request['user'], str) or
            not isinstance(request['schema'], dict) or not isinstance(request['options'], dict) or
            set(request['options']) != set(OPTION_DEFAULTS) or request['temperature'] != 0.0):
        raise ReviewSnapshotError('invalid_snapshot_request')
    if len(json.dumps(snapshot, ensure_ascii=False).encode('utf-8')) > MAX_SNAPSHOT_BYTES:
        raise ReviewSnapshotError('snapshot_size_limit')
    return request


def replay_review_input(snapshot, *, timeout_seconds=None, transport=None):
    """One independent sample of an unchanged request; no regeneration/cache."""
    from .call_review import bind_decision, ReviewStageError
    from .intent_anchor import _json_response, intent_request_diagnostic
    request = validate_snapshot(snapshot)
    if snapshot['client_budget']['transport_timeout_setting'] != os.environ.get('ICB_INTENT_LLM_TIMEOUT_SECONDS', '30'):
        raise ReviewSnapshotError('review_transport_timeout_changed')
    timeout = snapshot['client_budget']['timeout_seconds'] if timeout_seconds is None else timeout_seconds
    value = (transport or _json_response)(request['system'], request['user'], request['schema'],
        timeout_seconds=timeout, request_options=copy.deepcopy(request['options']))
    if value is None:
        raise ReviewStageError({**intent_request_diagnostic(), 'stage': 'review', 'failure': 'replay_output_unavailable'})
    packet = snapshot['packet']
    reverse = {'e'+str(i+1): row['id'] for i, row in enumerate(packet.get('observations', []))}
    if isinstance(value, dict) and isinstance(value.get('evidence_ids'), list):
        value = copy.deepcopy(value)
        value['evidence_ids'] = [('user' if x == 'user' else reverse.get(x, 'invalid_wire_reference:'+x))
                                 if isinstance(x, str) else x for x in value['evidence_ids']]
    try:
        return bind_decision(value, packet)
    except ValueError as error:
        raise ReviewStageError({'stage': 'review', 'status': 'invalid_review', 'failure': str(error)}) from None
