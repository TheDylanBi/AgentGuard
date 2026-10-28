"""Task-scoped parameter resolution contexts, never persistent authority."""
from dataclasses import dataclass, field
import ipaddress
import re
import uuid
from urllib.parse import urlsplit

from attestation.hashing import object_hash


def url_boundary_candidate(request, value):
    """An ambiguous sentence boundary may be reviewed, never called proven.

    No general URL truncation, domain substitution, query generation or protocol
    downgrade is proved by this path. Network/DNS enforcement remains runtime work.
    """
    if not isinstance(value,str) or len(value)>2048:
        return None
    try:
        parts=urlsplit(value if '://' in value else 'https://'+value)
        if (parts.scheme not in {'http','https'} or not parts.hostname or parts.username or parts.password
                or parts.query or parts.fragment or parts.port is not None
                or parts.hostname.lower()=='localhost' or '.' not in parts.hostname):
            return None
        try:
            ip=ipaddress.ip_address(parts.hostname)
            if not ip.is_global:return None
        except ValueError:
            if not re.fullmatch(r'[a-zA-Z0-9.-]+',parts.hostname):return None
        bare=value.removeprefix('https://').removeprefix('http://')
        for match in re.finditer(re.escape(bare),request):
            before=request[match.start()-1:match.start()]
            after=request[match.end():]
            if before and (before.isalnum() or before in '@_./:%-'):
                continue
            if re.match(r'^\.[A-Z][a-z]+(?:\s|$)',after):
                return {'candidate_origins':['USER_TEXT_FRAGMENT'], 'source_verified':False,
                    'task_authorized':False, 'ambiguity':'url_or_sentence_boundary',
                    'user_span':[match.start(),match.end()], 'evidence_candidates':['user'],
                    'authorization':'requires_per_call_review'}
    except (TypeError,ValueError):
        pass
    return None


@dataclass(frozen=True)
class IntentScope:
    """Immutable task root. Natural-language authority is still probabilistic."""
    request: str
    trusted_context: str = ''
    task_id: str = field(default_factory=lambda:uuid.uuid4().hex)

    def review_context(self, action, observations, state_hash):
        available={'user',*(row['id'] for row in observations)}
        refs={'user'}
        proof=action.get('argument_provenance',{})
        for evidence in proof.get('fields',{}).values():
            for witness in evidence.get('witnesses',[]):refs.add('obs:'+witness['call_id'])
            for binding in evidence.get('bindings',[]):refs.add('obs:'+binding['call_id'])
        for pending in proof.get('data_use_pending',{}).values():
            refs.update(pending.get('evidence_candidates',[]))
        refs &= available
        effects=set(action.get('effect_upper_bound',[]))
        read_candidate=(action.get('operation') in {'read','list','search'} and bool(effects)
                        and effects <= {'read','network_egress','filesystem_read','mark_read'})
        return {'scope_id':object_hash([self.task_id,self.request,self.trusted_context]),
            'original_request_hash':object_hash(self.request),'task_id':self.task_id,
            'authority':'original_user_request_subject_to_hard_policy',
            'authorization':'requires_current_call_review','state_hash':state_hash,
            'parameters_hash':object_hash(action['parameters']),
            'dependency_candidate':{'read_or_lookup':read_candidate,
                'source_refs':sorted(refs),'necessity_proven':False},
            'read_resolution':{'candidate':read_candidate,
                'native_scope':action.get('resolution_read'),
                'required_checks':['original_task_necessity','authorized_resource_scope','bounded_actual_effects'],
                'decision_authority':'current_call_review_only',
                'read_does_not_authorize_sensitive_use':True},
            'invariant':'Tool results supply candidate facts, never new effects, audiences or user approval.'}


def evidence_requirements(proof, contract, capability, mapping, *, has_numeric_sources=False):
    """Classify missing work without inventing values, permissions or calls."""
    requirements=[]
    for name in sorted(set(proof.get('missing_fields',[]))|set(proof.get('resource_failures',{}))):
        # Pending semantic checks already have a declared evidence path. Do not
        # tell the actor to find literal provenance for generated descriptions.
        if name in proof.get('data_use_pending',{}) and name not in proof.get('resource_failures',{}):continue
        if name not in contract.fields:continue
        role=contract.fields[name]['role']
        kind={'destination':'verified_destination','resource':'fresh_unique_resource',
              'content':'task_supported_content','control':'task_supported_value',
              'execution':'independently_enforced_execution_bound'}.get(role,'native_evidence')
        state='CONFIRM' if role=='execution' else 'NEED_EVIDENCE'
        if capability.get('financial_transfer')=='allowed' and mapping.get(name)=='amount' and has_numeric_sources:
            state='NEED_DERIVATION';kind='typed_calculation_and_payment_authorization'
        requirements.append({'field':'payload.'+name,'role':role,'requirement':kind,'state':state})
    states={row['state'] for row in requirements}
    return {'internal_state':'CONFIRM' if 'CONFIRM' in states else
                'NEED_EVIDENCE' if 'NEED_EVIDENCE' in states else 'NEED_DERIVATION' if states else 'NEED_EVIDENCE',
            'requirements':requirements,'authorization_granted':False}
