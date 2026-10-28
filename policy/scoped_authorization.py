"""Explicit trusted approval contracts, never model-generated authority.

Version 1 matches complete exact parameter sets and bounded typed derivations.
These task-local simulation grants require an operator-selected input file.
"""
import copy
import json
from datetime import date
from pathlib import Path

from attestation.hashing import object_hash
from .resource_provenance import at
from .typed_evidence import EvidenceError, number
from .tool_contract import typed_equal


def load_contracts(path=None):
    if path is None:
        return []
    def unique(pairs):
        value={}
        for k,v in pairs:
            if k in value:raise ValueError('Duplicate authorization contract key')
            value[k]=v
        return value
    raw=Path(path).read_bytes()
    if len(raw)>256_000:raise ValueError('Authorization contracts exceed bounded input')
    data=json.loads(raw,object_pairs_hook=unique)
    if not isinstance(data,dict) or set(data)!={'version','contracts'} or type(data['version']) is not int or data['version']!=1:
        raise ValueError('Invalid trusted authorization document')
    return validate_contracts(data['contracts'])


def validate_contracts(contracts):
    if not isinstance(contracts,list) or len(contracts)>64:
        raise ValueError('Invalid trusted authorization contracts')
    ids=set()
    for row in contracts:
        required={'id','request_hash','namespace','operation','resource_type','effect_upper_bound',
                  'destinations','parameters','max_uses','scale','reason'}
        if (not isinstance(row,dict) or set(row)!=required
                or any(not isinstance(row[k],str) or not row[k] for k in ('id','request_hash','operation','resource_type','reason'))
                or row['id'] in ids or type(row['max_uses']) is not int or not 1<=row['max_uses']<=20
                or type(row['scale']) is not int or not 0<=row['scale']<=6
                or not isinstance(row['parameters'],dict) or len(row['parameters'])>64
                or not isinstance(row['effect_upper_bound'],list)
                or any(not isinstance(x,str) for x in row['effect_upper_bound'])):
            raise ValueError('Invalid scoped authorization')
        ns=row['namespace']
        if (not isinstance(ns,dict) or set(ns) not in ({'path','equals'},{'path','sha256'})
                or not isinstance(ns['path'],list) or not 1<=len(ns['path'])<=12
                or any(not isinstance(x,str) or not x for x in ns['path'])
                or 'equals' in ns and (not isinstance(ns['equals'],str) or not ns['equals'])
                or 'sha256' in ns and not isinstance(ns['sha256'],str)):
            raise ValueError('Authorization needs a pinned namespace')
        for field,rule in row['parameters'].items():
            if not isinstance(field,str) or not isinstance(rule,dict) or set(rule) not in ({'eq'},{'derive'}):
                raise ValueError('Every effective parameter needs an exact or computed constraint')
        ids.add(row['id'])
    # Copy through JSON also refuses unsupported Python values/non-finite floats.
    return json.loads(json.dumps(contracts,allow_nan=False))


class ScopedAuthorization:
    def __init__(self, contracts, request, graph):
        self.contracts=validate_contracts(contracts or [])
        self.request_hash=object_hash(str(request));self.graph=graph
        self.uses={};self.spent_sources=set();self.records=[]
        self.last_failure=None

    def match(self, action, state):
        self.last_failure=None
        for scope in self.contracts:
            if (scope['request_hash']!=self.request_hash or scope['operation']!=action['operation']
                    or scope['resource_type']!=action['resource_type']):
                continue
            try:
                ns=scope['namespace'];current=at(state,ns['path'])
                if ('equals' in ns and not typed_equal(current,ns['equals'])
                        or 'sha256' in ns and object_hash(current)!=ns['sha256']):
                    raise EvidenceError('authorization_namespace_changed')
                if (set(scope['parameters'])!=set(action['parameters'])
                        or sorted(scope['effect_upper_bound'])!=sorted(action['effect_upper_bound'])
                        or not typed_equal(scope['destinations'],action.get('resolved_destinations'))):
                    raise EvidenceError('authorization_effect_or_parameter_scope_mismatch')
                if self.uses.get(scope['id'],0)>=scope['max_uses']:
                    raise EvidenceError('authorization_use_limit')
                proofs={};source_ids=set()
                financial='financial_transfer' in action['effect_upper_bound']
                if financial and ('equals' not in ns or set(scope['parameters'].get('recipient',{})) not in ({'eq'},{'derive'})
                                  or set(scope['parameters'].get('amount',{}))!={'derive'}):
                    raise EvidenceError('financial_scope_requires_verified_payee_and_typed_amount')
                if financial:
                    when=action['parameters'].get('date')
                    if not isinstance(when,str) or date.fromisoformat(when).isoformat()!=when:
                        raise EvidenceError('explicit_payment_date_required')
                for field,rule in scope['parameters'].items():
                    actual=action['parameters'][field]
                    if 'eq' in rule:
                        if not typed_equal(actual,rule['eq']):raise EvidenceError('authorization_literal_mismatch')
                        proofs[field]={'kind':'trusted_contract_literal','task_authorized':True,'value_hash':object_hash(actual)}
                    else:
                        proof=self.graph.evaluate(rule['derive'],state=state,
                            account=ns.get('equals','namespace:'+object_hash(current)),scale=scope['scale'])
                        if proof['type'] in {'money','ratio'}:
                            if number(actual)!=number(proof['value']):raise EvidenceError('claimed_calculation_mismatch')
                        elif not typed_equal(actual,proof['value']):raise EvidenceError('claimed_calculation_mismatch')
                        if financial and field=='amount' and (proof['type']!='money' or number(actual)<=0):
                            raise EvidenceError('invalid_financial_result')
                        if financial and field=='recipient':
                            root=next(node for node in proof['nodes'] if node['id']==proof['root'])
                            if (proof['type']!='account' or root['operator']!='native_field'
                                    or len(proof['sources'])!=1 or not isinstance(actual,str) or not actual):
                                raise EvidenceError('payee_needs_native_account_binding')
                        proofs[field]={'kind':'verified_derivation','calculation':proof,'task_authorized':True}
                        source_ids.update(row['identity'] for row in proof['sources'])
                if financial and source_ids & self.spent_sources:
                    raise EvidenceError('financial_source_already_consumed')
                self.last_failure=None
                return {'contract_id':scope['id'],'contract_hash':object_hash(scope),
                    'use_index':self.uses.get(scope['id'],0),
                    'request_hash':self.request_hash,'task_id':self.graph.task_id,
                    'parameters_hash':object_hash(action['parameters']),'state_hash':object_hash(state),
                    'proofs':proofs,'source_ids':sorted(source_ids),'financial':financial}
            except (ValueError,TypeError,KeyError) as error:
                self.last_failure=str(error) if isinstance(error,EvidenceError) else 'invalid_contract_evidence'
        return None

    def consume(self, match, action, state):
        fresh=self.match(action,state)
        if fresh is None or object_hash(fresh)!=object_hash(match):
            raise EvidenceError('authorization_changed_before_execution')
        key=match['contract_id'];self.uses[key]=self.uses.get(key,0)+1
        if match['financial']:self.spent_sources.update(match['source_ids'])
        self.records.append(copy.deepcopy(match))

    def digest(self):
        return object_hash({'contracts':self.contracts,'uses':self.uses,'spent_sources':sorted(self.spent_sources)})
