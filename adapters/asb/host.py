"""Serialized authorization/dispatch for ASB fixed-string simulated tools."""
import copy
from contextlib import contextmanager
from pathlib import Path
import threading
import time

from attestation.hashing import object_hash
from gateway.api_schema import Action, CapabilityDeclaration, ToolRegistrationRequest
from policy.authorize import check_hard_boundaries
from policy.call_review import CallReviewer
from policy.review_snapshot import capture_review_inputs
from policy.capability_registry import CapabilityRegistry
from policy.engine import PolicyEngine
from .source import PolicyDenied
from .reliability import DecisionContinuity, asb_review_call, shared_asb_review_call, feedback
from .tool_contracts import ToolContracts, implementation_identity
from .task_context import context_text, task_checkpoint

PROJECT = Path(__file__).resolve().parents[2]


class ASBHost:
    def __init__(self, *, mode, user_request, catalog, signer, audit,
                 tool_classes, business_policy=None, reviewer=None, deadline=None,
                 tool_contracts=None, runtime_hash=None, review_profile='shared', require_tool_contracts=False,
                 task_context=None, task_requirements=None):
        if mode not in {'baseline', 'guarded'}:
            raise ValueError('Invalid ASB mode')
        self.mode, self.audit = mode, audit
        self._user_request = str(user_request)
        self._task_context = copy.deepcopy(task_context)
        self._task_requirements = copy.deepcopy(task_requirements if task_requirements is not None else
                                                (task_context or {}).get('requirements', []))
        self._progress_assessment = None
        if task_context is not None and task_context['request_hash'] != object_hash(self._user_request):
            raise ValueError('Trusted clarification belongs to another task')
        self.contracts = tool_contracts or ToolContracts()
        self.runtime_hash = runtime_hash
        self.require_tool_contracts = bool(require_tool_contracts)
        if self.require_tool_contracts and not self.contracts.entries:
            raise ValueError('Required tool provenance needs independent operator declarations')
        self.assurance = {name: self.contracts.resolve(name, spec, runtime_hash) for name, spec in catalog.items()}
        self.continuity = DecisionContinuity()
        self.catalog = copy.deepcopy(catalog)
        self._tool_context_pin = object_hash([self.catalog, self.contracts.snapshot(), self.assurance])
        self.tool_classes = {cls: cls.run for cls in tool_classes}
        self.engine = PolicyEngine(PROJECT / 'policy/policies', business_policy)
        self.registry = CapabilityRegistry(signer)
        self.certificates = {}
        # Identical declarations for every native ASB simulation tool. No attack
        # label, goal, expected achievement or privileged "normal tool" list.
        for name, spec in self.catalog.items():
            cert = self.registry.register(ToolRegistrationRequest(tool_id=name,
                label=name, declared_capabilities=CapabilityDeclaration(actions=[name]),
                implementation_version='asb-fixed-string-simulation-v1',
                implementation_hash=object_hash(spec)))
            self.certificates[name] = cert.capability_cert_id
        if review_profile not in {'shared', 'asb'}:
            raise ValueError('Unknown ASB review profile')
        self.reviewer = (reviewer or CallReviewer(user_request, trusted_context=context_text(task_context),
            caller=asb_review_call if review_profile == 'asb' else shared_asb_review_call)) if mode == 'guarded' else None
        if self.reviewer is not None:
            if (self.reviewer.original_user_request != self.user_request or
                    self.reviewer._trusted_context != context_text(self._task_context)):
                raise ValueError('Reviewer authority differs from host task context')
            self.reviewer.deadline = deadline
        self._authority_pin = self._authority_state()
        self.deadline = deadline
        self.events = []
        self.review_inputs = []
        self.counts = {key: 0 for key in ('ALLOW', 'BLOCK', 'CONFIRM', 'executed', 'tool_errors')}
        self.failure = None
        self.failure_diagnostic = None
        self.pending = None
        self._completion = None
        self.lock = threading.RLock()

    @property
    def user_request(self):
        return self._user_request

    @property
    def task_context(self):
        return copy.deepcopy(self._task_context)

    def _authority_state(self):
        return object_hash([self.user_request, self._task_context,
            [self.reviewer.original_user_request, self.reviewer._trusted_context]
            if self.reviewer is not None else None])

    def task_progress(self):
        return task_checkpoint(self.user_request, self._task_context, self.events,
                               self._task_requirements, self._progress_assessment)

    def record_progress_assessment(self, assessment):
        """Record a model opinion for diagnostics; it grants no permission."""
        with self.lock:
            value = copy.deepcopy(assessment)
            requirement_ids = {row['id'] for row in self._task_requirements}
            if {row['id'] for row in value.get('requirement_status', [])} != requirement_ids:
                raise ValueError('Progress assessment requirements changed')
            self._progress_assessment = value

    def completion_eligibility(self, name):
        """An eligibility check supplies no permission and never infers effects."""
        if name not in self.catalog:
            return {'eligible_for_review': False, 'reason': 'unknown_tool'}
        if any(row['tool'] == name for row in self.events):
            return {'eligible_for_review': False, 'reason': 'previously_attempted'}
        assurance = self.assurance[name]
        if assurance['contract_complete'] and (
                assurance['operation'] not in {'read', 'list', 'search'} or
                set(assurance['effect_upper_bound']) - {'read', 'filesystem_read', 'network_egress'} or
                assurance['capability']['writes']):
            return {'eligible_for_review': False, 'reason': 'declared_non_query_effects'}
        return {'eligible_for_review': True, 'reason': 'host_authorization_still_required',
            'effect_assurance': 'operator_declared' if assurance['contract_complete'] else
                                'unknown_not_proved_read_only'}

    @contextmanager
    def completion_scope(self, names):
        with self.lock:
            if self._completion is not None:
                raise RuntimeError('Nested completion dispatch scope')
            self._completion = {'names': frozenset(names),
                'prior': frozenset(row['tool'] for row in self.events), 'attempts': {}}
            self._completion['pin'] = object_hash([sorted(self._completion['names']),
                                                   sorted(self._completion['prior'])])
            try:
                yield
            finally:
                self._completion = None

    def _completion_boundary(self, name, call_id):
        if self._completion is None:
            return {'verdict': 'PASS', 'rule': 'completion.not_active'}
        scope = self._completion
        if object_hash([sorted(scope['names']), sorted(scope['prior'])]) != scope['pin']:
            raise RuntimeError('Completion scope changed during authorization')
        if name not in scope['names'] or name in scope['prior']:
            return {'verdict': 'BLOCK', 'rule': 'completion.not_an_omitted_query'}
        previous = scope['attempts'].setdefault(name, call_id)
        if previous != call_id:
            return {'verdict': 'BLOCK', 'rule': 'completion.duplicate'}
        assurance = self.assurance[name]
        if assurance['contract_complete'] and (
                assurance['operation'] not in {'read', 'list', 'search'} or
                set(assurance['effect_upper_bound']) - {'read', 'filesystem_read', 'network_egress'} or
                assurance['capability']['writes']):
            return {'verdict': 'BLOCK', 'rule': 'completion.non_query_effects'}
        return {'verdict': 'PASS', 'rule': 'completion.pending_authorization'}

    def actor_tool_context(self):
        """Use the same independent declarations in planning and review.

        This is conditional on an explicit operator manifest. Native catalog
        claims alone never generate a narrower, trusted purpose.
        """
        declared = {name: copy.deepcopy(value) for name, value in self.assurance.items()
                    if value['contract_complete']}
        if not declared:
            return None
        return {'source': 'host_loaded_operator_contracts', 'tools': declared,
            'task_permission': False,
            'limits': 'These are independently supplied operator assertions, not observed effects. '
                'Actual instances must pass pins at dispatch. Preserve all read/write/communication '
                'effects. No sub-operation selector or real financial data is added to ASB. '
                'Tools without a declaration remain unverified; no tool is mandatory.'}

    def raise_if_failed(self):
        if self.failure is not None:
            raise RuntimeError('ASB evaluation incomplete: ' + self.failure)

    def _audit(self, event):
        self.audit.append(copy.deepcopy(event))

    def _capture_review(self, value):
        self._audit({'event': 'asb_review_input', 'call_id': value['packet']['call_id'],
                     'snapshot_hash': value['snapshot_hash']})
        self.review_inputs.append(copy.deepcopy(value))

    def _boundary(self, action, name, tool):
        if self._authority_state() != self._authority_pin:
            raise RuntimeError('Trusted task authority changed during execution')
        if object_hash([self.catalog, self.contracts.snapshot(), self.assurance]) != self._tool_context_pin:
            raise RuntimeError('Tool declarations changed after planning context was bound')
        cert = self.registry.verify(self.certificates[name])
        if cert is None:
            return {'verdict': 'BLOCK', 'rule': 'capability.revoked'}
        try:
            assurance = self.contracts.resolve(name, self.catalog[name], self.runtime_hash, tool)
        except ValueError:
            return {'verdict': 'BLOCK', 'rule': 'tool.contract_pin_mismatch'}
        if self.require_tool_contracts:
            if not assurance['catalog_claim_verified']:
                return {'verdict': 'BLOCK', 'rule': 'tool.provenance_required'}
            if not assurance['contract_complete']:
                return {'verdict': 'BLOCK', 'rule': 'tool.contract_upgrade_required'}
            if not assurance['instance_verified']:
                return {'verdict': 'BLOCK', 'rule': 'tool.instance_unverified'}
        return check_hard_boundaries(action, capability=cert['declared_capabilities'],
            engine=self.engine, taint_state={'dirty': False, 'objects': []})

    def dispatch(self, name, tool, arguments):
        with self.lock:
            self.raise_if_failed()
            try:
                if self.deadline is not None and time.monotonic() >= self.deadline:
                    raise TimeoutError('task_deadline')
                if self._authority_state() != self._authority_pin:
                    raise RuntimeError('Trusted task authority changed during execution')
                if arguments is not None:
                    raise ValueError('Native ASB argument contract changed')
                if name not in self.catalog or type(tool) not in self.tool_classes:
                    raise ValueError('Unregistered simulated tool implementation')
                if getattr(tool.run, '__func__', None) is not self.tool_classes[type(tool)]:
                    raise ValueError('Simulated tool implementation changed')
                call_id = 'call-' + str(len(self.events) + 1)
                instance_before = implementation_identity(tool)
                semantic = {'version': 1, 'operation': 'invoke_simulated_tool',
                    'resource_type': 'asb_simulated_tool', 'tool_name': name,
                    'tool_description': self.catalog[name]['description'],
                    'parameters': {}, 'parameter_roles': {}, 'effect_upper_bound': [],
                    'execution_model': 'ASB fixed-string simulation, no executed parameters; '
                                       'judge the described tool purpose against the original task'}
                # Preliminary metadata cannot grant trust; the boundary below
                # verifies the actual instance before any semantic review.
                semantic['tool_assurance'] = copy.deepcopy(self.assurance[name])
                if self.assurance[name]['contract_complete']:
                    semantic['operation'] = self.assurance[name]['operation']
                    semantic['effect_upper_bound'] = self.assurance[name]['effect_upper_bound']
                    cap = self.assurance[name]['capability']
                    semantic['tool_description'] = cap['purpose']
                    semantic['resource_type'] = cap['resource_type']
                    semantic['declared_scope'] = copy.deepcopy(cap)
                    semantic['execution_model'] = ('Operator-asserted capability upper bound for a fixed-string '
                        'simulation; scope is not an observed effect or task permission')
                    semantic['tool_description_trust'] = 'operator_assertion'
                else:
                    semantic['effect_assurance'] = 'business_effects_unknown_not_proved_read_only'
                    semantic['tool_description_trust'] = 'unverified_catalog_claim'
                action = Action(type=name, target=name, payload={})
                event = {'id': call_id, 'tool': name, 'native_arguments': None,
                         'origin': 'completion' if self._completion is not None else 'native',
                         'executed': False, 'event': 'asb_tool_call',
                         'task_authorization': {'status': 'not_reviewed'},
                         'tool_trust': {'required': self.require_tool_contracts,
                            'contract_hash': self.assurance[name].get('contract_hash'),
                            'contract_complete': self.assurance[name]['contract_complete']}}
                self.events.append(event)
                decision = {'verdict': 'ALLOW', 'rule': 'baseline'}
                completion = self._completion_boundary(name, call_id)
                if completion['verdict'] != 'PASS':
                    decision = completion
                elif self.mode == 'guarded':
                    decision = self._boundary(action, name, tool)
                    event['hard_check'] = copy.deepcopy(decision)
                    if decision['verdict'] == 'PASS':
                        semantic['tool_assurance'] = self.contracts.resolve(name, self.catalog[name], self.runtime_hash, tool)
                        event['tool_trust']['instance_verified'] = semantic['tool_assurance']['instance_verified']
                        identity = [self.certificates[name], self.engine.business_policy.fingerprint]
                        key = self.continuity.key(name, semantic, identity)
                        cached, prior = self.continuity.prepare(key, self.reviewer.observations)
                        if prior:
                            semantic['prior_authorization'] = prior
                        binding = object_hash([self.certificates[name], self.catalog[name],
                            self._authority_state(),
                            self.engine.business_policy.fingerprint, self.contracts.snapshot(),
                            semantic, self.reviewer.observations])
                        with capture_review_inputs(self._capture_review):
                            reviewed = cached or self.reviewer.check(call_id, name, {}, semantic, binding)
                        reviewed, gap = self.continuity.finish(key, reviewed, self.reviewer.observations, prior)
                        event['authorization_continuity'] = 'cached_negative' if cached else gap or 'reviewed'
                        if gap:
                            self._audit({'id': call_id + ':continuity', 'event': 'asb_authorization_gap_unresolved',
                                         'tool': name, 'rule': gap})
                        verdict = {'allow': 'ALLOW', 'deny': 'BLOCK', 'needs_evidence': 'CONFIRM'}[reviewed['decision']]
                        decision = {'verdict': verdict, 'rule': 'review.' + reviewed['code']}
                        event['task_authorization'] = {key: copy.deepcopy(reviewed.get(key)) for key in
                            ('decision', 'code', 'fields', 'evidence_ids')}
                        event['task_authorization']['status'] = 'cached' if cached else 'reviewed'
                        if verdict == 'ALLOW':
                            if binding != object_hash([self.certificates[name], self.catalog[name],
                                    self._authority_state(),
                                    self.engine.business_policy.fingerprint, self.contracts.snapshot(),
                                    semantic, self.reviewer.observations]):
                                raise RuntimeError('Authorization binding changed')
                            hard = self._boundary(action, name, tool)
                            event['execution_hard_check'] = copy.deepcopy(hard)
                            if hard['verdict'] != 'PASS':
                                decision = hard
                verdict = decision['verdict']
                if verdict not in {'ALLOW', 'BLOCK', 'CONFIRM'}:
                    raise ValueError('Unknown policy verdict')
                event.update(verdict=verdict, rule=decision['rule'])
                self.counts[verdict] += 1
                # Log before the only execution point; logging failure stops it.
                self._audit(event)
                if verdict != 'ALLOW':
                    raise PolicyDenied(verdict, feedback(verdict, decision['rule'], name))
                if self.deadline is not None and time.monotonic() >= self.deadline:
                    raise TimeoutError('task_deadline')
                if self._completion_boundary(name, call_id)['verdict'] != 'PASS':
                    raise RuntimeError('Completion call binding changed before execution')
                if (implementation_identity(tool) != instance_before or
                        getattr(tool.run, '__func__', None) is not self.tool_classes[type(tool)]):
                    raise RuntimeError('Authorized implementation or instance changed')
                try:
                    result = tool.run(arguments)
                except Exception:
                    self.counts['tool_errors'] += 1
                    raise
                if not isinstance(result, str):
                    raise TypeError('ASB simulated tool must return a string')
                event['executed'] = True
                self.counts['executed'] += 1
                self.pending = (call_id, name, semantic)
                self._audit({'id': call_id + ':executed', 'event': 'asb_tool_executed',
                             'tool': name, 'result_hash': object_hash(result)})
                return result
            except PolicyDenied:
                raise
            except Exception as error:
                self.failure = type(error).__name__
                if hasattr(error, 'diagnostic'):
                    self.failure_diagnostic = copy.deepcopy(error.diagnostic)
                # No raw exception message: network exceptions may contain URLs
                # or credentials. The wrapper rethrows after ASB's broad catch.
                raise RuntimeError('ASB host failed: ' + self.failure) from None

    def observe(self, name, arguments, result):
        """Called AFTER ASB appends OPI; reviewer sees exactly delivered data."""
        with self.lock:
            try:
                if self.pending is None or self.pending[1] != name:
                    raise RuntimeError('No matching execution for observation')
                call_id, _, semantic = self.pending
                if self.reviewer is not None:
                    self.reviewer.observe(call_id, name, {}, result, None, semantic_action=semantic)
                self._audit({'id': call_id + ':observation', 'event': 'asb_observation_delivered',
                             'tool': name, 'trust': 'untrusted_tool_data', 'result_hash': object_hash(result)})
                self.pending = None
            except Exception as error:
                self.failure = type(error).__name__
                raise RuntimeError('ASB observation failed') from None
