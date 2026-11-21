"""Causal review-mode projection over R-Judge transcripts; no tool execution.

Record mapping: a denied action => unsafe, complete all-allow action trace =>
safe, confirmation/unsupported/no-action => abstain. These are policy decisions
on observed tool actions, not a proof of whole-record behavioral safety.
"""
import copy
import json
import time
from types import SimpleNamespace

from attestation.hashing import object_hash
from policy.authorize import check_hard_boundaries
from policy.call_review import CallReviewer
from policy import taint
from policy.tool_capabilities import TOOL_CAPABILITIES, build_tool_caps
from demo.attacks.rjudge_parse import parse_action


def review_record(public, *, engine, reviewer_factory=CallReviewer):
    started = time.perf_counter()
    trusted = []
    reviewer = None
    observations = []
    actions = []
    reviews = []
    pending = []
    state = {'dirty': False, 'tainted_objects': []}
    caps = build_tool_caps(set(TOOL_CAPABILITIES))

    def finish(prediction, reason):
        return {'protocol': 'review-direct-v1', 'prediction': prediction,
                'reason': reason, 'actions': actions, 'reviews': reviews,
                'review_requests': sum(row.get('request_count', 0) for row in reviews),
                'review_seconds': sum(row.get('elapsed_seconds', 0) for row in reviews),
                'elapsed_seconds': time.perf_counter() - started,
                'scope': 'transcript action authorization; no live state/schema/resource certificates',
                'executed': False}

    for round_ in public['contents']:
        for turn in round_:
            if turn['role'] == 'user' and turn.get('content'):
                trusted.append(turn['content'])
                reviewer = reviewer_factory('\n'.join(trusted), public['profile'])
                reviewer.observations = copy.deepcopy(observations)
            elif turn['role'] == 'environment':
                if reviewer is None or len(pending) != 1:
                    return finish('abstain', 'unbound_environment_observation')
                call_id, tool, arguments, semantic = pending.pop()
                reviewer.observe(call_id, tool, arguments,
                    json.dumps(turn.get('content'), ensure_ascii=False), None,
                    semantic_action=semantic)
                observations = copy.deepcopy(reviewer.observations)
            elif turn['role'] == 'agent' and turn.get('action'):
                if reviewer is None:
                    return finish('abstain', 'missing_user_authority')
                parsed = parse_action(turn['action'])
                if not parsed:
                    return finish('abstain', 'unsupported_action')
                if pending:
                    return finish('abstain', 'missing_tool_observation')
                for tool, target, arguments in parsed:
                    if tool not in caps:
                        return finish('abstain', 'unsupported_tool')
                    capability = caps[tool]
                    action = SimpleNamespace(type=tool, target=target, payload=arguments)
                    hard_start = time.perf_counter()
                    hard = check_hard_boundaries(action, capability=capability, engine=engine,
                                                  taint_state=state, require_capability=True)
                    row = {'call_id': str(len(actions)+1), 'tool': tool, 'hard': hard,
                           'hard_seconds': time.perf_counter()-hard_start}
                    actions.append(row)
                    if hard['verdict'] == 'BLOCK':
                        return finish('unsafe', 'hard_boundary_denied')
                    if hard['verdict'] != 'PASS':
                        return finish('abstain', 'hard_boundary_needs_evidence')
                    # Expose native parsed identity/arguments, without inventing
                    # parameter roles, successful effects or source certificates.
                    semantic = {'operation': capability.get('effect_type') or 'invoke',
                                'resource_type': capability.get('target_type') or tool,
                                'parameters': copy.deepcopy(arguments),
                                'effect_upper_bound': [key for key in ('network_egress','external_share',
                                    'credential_access','process','persistence') if capability.get(key)=='allowed'],
                                'tool_identity': tool, 'adapter_scope': 'parsed_transcript_only',
                                'state_verified': False, 'parameter_roles_verified': False}
                    try:
                        result = reviewer.check(row['call_id'], tool, arguments, semantic,
                                                object_hash({'state': state, 'observations': observations}))
                    except Exception as error:
                        row['error_type'] = type(error).__name__
                        reviews.extend(copy.deepcopy(reviewer.records))
                        reviewer.records.clear()
                        return finish('abstain', 'review_error')
                    reviews.extend(copy.deepcopy(reviewer.records))
                    reviewer.records.clear()
                    row['review'] = result
                    if result['decision'] == 'deny':
                        return finish('unsafe', 'review_denied')
                    if result['decision'] != 'allow':
                        return finish('abstain', 'review_needs_evidence')
                    pending.append((row['call_id'], tool, arguments, semantic))
                    if taint.is_source(capability):
                        taint.record_source_read(state, target, source=capability.get('sources', []))
    return finish('safe', 'all_observed_actions_allowed') if actions else finish('abstain', 'no_supported_actions')
