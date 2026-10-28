"""Operator-supplied semantic deliverables, never task authority or a tool checklist."""
import copy
import json
from pathlib import Path
import re

from attestation.hashing import object_hash


PROTOCOL = 'asb-task-requirements-v1'
MAX_BYTES = 128_000


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate task-requirement key')
        value[key] = item
    return value


def _text(value, limit=4096):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit


class TaskRequirements:
    def __init__(self, path=None):
        self._data = None
        self._entries = {}
        self.fingerprint = None
        if path is None:
            return
        raw = Path(path).read_bytes()
        if len(raw) > MAX_BYTES:
            raise ValueError('Task requirements exceed budget')
        data = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_object)
        if (not isinstance(data, dict) or set(data) != {'version', 'issuer', 'reference', 'tasks'}
                or type(data['version']) is not int or data['version'] != 1
                or not _text(data['issuer'], 512) or not _text(data['reference'], 2048)
                or not isinstance(data['tasks'], list) or not 1 <= len(data['tasks']) <= 256):
            raise ValueError('Invalid task requirements')
        for task in data['tasks']:
            if (not isinstance(task, dict) or set(task) != {'request_hash', 'requirements'}
                    or not isinstance(task['request_hash'], str)
                    or not re.fullmatch(r'sha256:[0-9a-f]{64}', task['request_hash'])
                    or task['request_hash'] in self._entries
                    or not isinstance(task['requirements'], list)
                    or not 1 <= len(task['requirements']) <= 32):
                raise ValueError('Invalid or duplicate task requirement binding')
            identifiers = set()
            for row in task['requirements']:
                if (not isinstance(row, dict) or set(row) != {'id', 'description'}
                        or not all(_text(v) for v in row.values())
                        or not re.fullmatch(r'[a-z][a-z0-9_]{0,47}', row['id'])
                        or row['id'] in identifiers):
                    raise ValueError('Invalid task requirement')
                identifiers.add(row['id'])
            if len(json.dumps(task, ensure_ascii=False).encode('utf-8')) > 24_000:
                raise ValueError('One task requirement set exceeds budget')
            self._entries[task['request_hash']] = copy.deepcopy(task['requirements'])
        self._data = copy.deepcopy(data)
        self.fingerprint = object_hash(data)

    def snapshot(self):
        return copy.deepcopy(self._data)

    def for_request(self, original_request):
        if self._data is None:
            return []
        request_hash = object_hash(original_request)
        if request_hash not in self._entries:
            raise ValueError('Selected task has no exact semantic requirement binding')
        return copy.deepcopy(self._entries[request_hash])
