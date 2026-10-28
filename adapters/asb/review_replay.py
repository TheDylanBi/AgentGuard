"""Repeat a frozen semantic review offline; never dispatch tools or seek grants."""
import argparse
import json
from pathlib import Path
import time

from policy.review_snapshot import replay_review_input, validate_snapshot, MAX_SNAPSHOT_BYTES, ReviewSnapshotError
from policy.call_review import ReviewStageError
from .run import write_json


def repeat_snapshot(snapshot, repeats=5, timeout_seconds=None, runner=None, on_update=None):
    if type(repeats) is not int or not 1 <= repeats <= 20:
        raise ValueError('Review repeats must be 1..20')
    validate_snapshot(snapshot)
    result = {'protocol': 'review-replay-v1', 'snapshot_hash': snapshot['snapshot_hash'],
        'planned': repeats, 'status': 'running', 'attempts': [],
        'original_timeout_seconds': snapshot['client_budget']['timeout_seconds'],
        'timeout_override_seconds': timeout_seconds,
        'scope': 'Independent offline samples; no tool execution, caching, recovery or authorization consumption'}
    try:
        for index in range(repeats):
            started = time.monotonic()
            row = {'sample': index+1}
            try:
                row['decision'] = (runner or replay_review_input)(snapshot, timeout_seconds=timeout_seconds)
                row['status'] = 'valid'
            except ReviewStageError as error:
                row.update(status='error', diagnostic=error.diagnostic)
            row['elapsed_seconds'] = round(time.monotonic()-started, 4)
            result['attempts'].append(row)
            if on_update:
                on_update(result)
            if row.get('diagnostic', {}).get('http_status') in {401, 402, 403}:
                break
    finally:
        rows = result['attempts']
        valid = [r for r in rows if r['status'] == 'valid']
        result.update(status='complete' if len(rows) == repeats else 'incomplete',
                      valid=len(valid), errors=len(rows)-len(valid), unattempted=repeats-len(rows),
                      decisions={d: sum(r['decision']['decision'] == d for r in valid)
                                 for d in ('allow', 'deny', 'needs_evidence')},
                      decision_disagreement=len({r['decision']['decision'] for r in valid}) > 1)
        if on_update:
            on_update(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True, help='Host-created review-inputs.json or single snapshot')
    parser.add_argument('--index', type=int, default=0)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--timeout', type=float, help='Explicit override, recorded as a different client budget')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.timeout is not None and not 0 < args.timeout <= 120:
        parser.error('timeout must be 0..120 seconds')
    if args.input.stat().st_size > 20*MAX_SNAPSHOT_BYTES:
        parser.error('Input file exceeds the review replay limit')
    data = json.loads(args.input.read_text(encoding='utf-8-sig'))
    rows = data if isinstance(data, list) else [data]
    if not 0 <= args.index < len(rows):
        parser.error('snapshot index is out of range')
    if args.output.exists():
        parser.error('output exists; preserve earlier replay results')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = repeat_snapshot(rows[args.index], args.repeats, args.timeout,
            on_update=lambda value: write_json(args.output, value))
    except ReviewSnapshotError as error:
        parser.error(str(error))
    print(json.dumps({k: result[k] for k in ('status', 'planned', 'valid', 'errors', 'decisions', 'decision_disagreement')}))
    return 0 if result['status'] == 'complete' and not result['errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
