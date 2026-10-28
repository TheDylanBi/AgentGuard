"""Task-local, snapshot-backed typed facts and a bounded arithmetic DAG.

Calculations prove correspondence to declared inputs, never user permission.
No model expressions are executed: the DSL has a closed set of operators.
"""
import copy
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation, localcontext, ROUND_HALF_EVEN, ROUND_HALF_UP
import json
import time
import uuid

from attestation.hashing import object_hash
from .resource_provenance import at, located
from .runtime_bindings import json_value
from .tool_contract import typed_equal


class EvidenceError(ValueError):
    pass


def number(value, *, computed=False):
    if type(value) not in (str, int, float, Decimal):
        raise EvidenceError('invalid_decimal')
    try:
        result=Decimal(str(value))
    except InvalidOperation:
        raise EvidenceError('invalid_decimal') from None
    if not result.is_finite() or result.copy_abs()>Decimal('1000000000000') or abs(result.as_tuple().exponent)>(64 if computed else 24):
        raise EvidenceError('decimal_out_of_bounds')
    return result


def validate_typed_results(spec):
    declarations=spec.get('typed_results',[])
    if not isinstance(declarations,list) or len(declarations)>8 or declarations and not spec.get('schema_hash'):
        raise ValueError('Typed results require pinned bounded declarations')
    for row in declarations:
        if (not isinstance(row,dict) or set(row)!={'label','path','collection','key','account','fields','scale','reason'}
                or not isinstance(row['label'],str) or not row['label']
                or not isinstance(row['key'],str) or not row['key']
                or type(row['scale']) is not int or not 0<=row['scale']<=6
                or not isinstance(row['fields'],dict) or not row['fields']
                or any(not isinstance(k,str) or v not in {'money','date','account','text','ratio','identifier','boolean'} for k,v in row['fields'].items())
                or any(not isinstance(row[k],list) or len(row[k])>12 or any(not isinstance(p,str) or not p for p in row[k])
                       for k in ('path','collection','account'))
                or not row['collection'] or not row['account']
                or not isinstance(row['reason'],str) or not row['reason'].strip()):
            raise ValueError('Invalid typed native result declaration')


class EvidenceGraph:
    def __init__(self, *, clock=time.monotonic):
        self.task_id=uuid.uuid4().hex
        self.clock=clock
        self.records={}

    def observe(self, spec, result, error, state, call_id):
        if error is not None or not spec.get('typed_results'):
            return
        try:
            native=json_value(result)
            size=len(json.dumps(native,ensure_ascii=False,allow_nan=False).encode('utf-8'))
        except (ValueError,TypeError,RecursionError,OverflowError):
            return
        if size>500_000:
            return
        for declaration in spec['typed_results']:
            try:
                collection=at(state,declaration['collection']);account=at(state,declaration['account'])
                if not isinstance(account,str) or not account:
                    continue
                objects=list(collection.values()) if isinstance(collection,dict) else collection
                if not isinstance(objects,list) or len(objects)>2048:
                    continue
                for path,entity in located(native,declaration['path']):
                    if not isinstance(entity,dict) or type(entity.get(declaration['key'])) not in (str,int):
                        continue
                    key=entity[declaration['key']]
                    matches=[row for row in objects if isinstance(row,dict) and typed_equal(row.get(declaration['key']),key)]
                    if len(matches)!=1 or not typed_equal(matches[0],entity):
                        continue
                    identity=object_hash([account,declaration['label'],key,declaration['collection']])
                    self.records[identity]={'identity':identity,'task_id':self.task_id,'account':account,
                        'declaration':copy.deepcopy(declaration),'entity':copy.deepcopy(entity),
                        'entity_hash':object_hash(entity),'call_id':call_id,'path':list(path),
                        'result_hash':object_hash(native),'created':self.clock()}
                    if len(self.records)>1024:
                        self.records.pop(next(iter(self.records)))
            except (ValueError,TypeError,KeyError):
                continue

    def evaluate(self, expression, *, state, account, scale=2):
        if type(scale) is not int or not 0<=scale<=6 or not isinstance(account,str) or not account:
            raise EvidenceError('invalid_calculation_scope')
        try:
            serialized=json.dumps(expression,allow_nan=False)
        except (ValueError,TypeError,RecursionError):
            raise EvidenceError('invalid_calculation_document') from None
        if len(serialized)>32_000:
            raise EvidenceError('calculation_too_large')
        nodes=[];sources={};count=0
        quantum=Decimal(1).scaleb(-scale)
        def parse(value,kind):
            if kind == 'boolean':
                if type(value) is not bool:raise EvidenceError('invalid_boolean_source')
                return value
            if kind == 'identifier':
                if type(value) not in (str,int) or isinstance(value,str) and not value:
                    raise EvidenceError('invalid_identifier_source')
                return value
            if kind in {'money','ratio'}:
                value=number(value)
                if kind=='money' and (value<0 or value!=value.quantize(quantum)):
                    raise EvidenceError('invalid_money_precision_or_sign')
                return value
            if not isinstance(value,str):
                raise EvidenceError('invalid_typed_text')
            if kind=='date':
                if date.fromisoformat(value).isoformat()!=value:
                    raise EvidenceError('invalid_date')
            return value
        def visit(expr,depth=0):
            nonlocal count
            count+=1
            if count>128 or depth>12 or not isinstance(expr,dict):
                raise EvidenceError('calculation_bounds_exceeded')
            proof={}
            if set(expr)=={'literal','type'} and expr['type'] in {'money','ratio','date','account','text'}:
                kind=expr['type'];value=parse(expr['literal'],kind)
                proof={'operator':'trusted_contract_literal','type':kind,'value':str(value)}
            elif set(expr)=={'source'}:
                ref=expr['source']
                if not isinstance(ref,dict) or not {'label','key','field'}<=set(ref) or set(ref)-{'label','key','field','where'}:
                    raise EvidenceError('invalid_source_reference')
                matches=[row for row in self.records.values() if row['account']==account
                         and row['declaration']['label']==ref['label']
                         and typed_equal(row['entity'].get(row['declaration']['key']),ref['key'])]
                if len(matches)!=1:
                    raise EvidenceError('missing_or_ambiguous_typed_source')
                row=matches[0];decl=row['declaration'];entity=row['entity']
                collection=at(state,decl['collection']);objects=list(collection.values()) if isinstance(collection,dict) else collection
                current=[x for x in objects if isinstance(x,dict) and typed_equal(x.get(decl['key']),ref['key'])]
                if (at(state,decl['account'])!=account or not 0<=self.clock()-row['created']<=300
                        or len(current)!=1 or object_hash(current[0])!=row['entity_hash']):
                    raise EvidenceError('typed_source_stale_or_wrong_account')
                where=ref.get('where',{})
                if not isinstance(where,dict) or any(not typed_equal(entity.get(k),v) for k,v in where.items()):
                    raise EvidenceError('typed_source_business_selector_mismatch')
                kind=decl['fields'].get(ref['field'])
                if kind is None or decl['scale']!=scale:
                    raise EvidenceError('typed_source_type_or_unit_mismatch')
                value=parse(entity[ref['field']],kind)
                proof={'operator':'native_field','type':kind,'value':str(value),'source_identity':row['identity'],
                       'call_id':row['call_id'],'path':row['path']+[ref['field']],
                       'result_hash':row['result_hash'],'entity_hash':row['entity_hash']}
                sources[row['identity']]={'identity':row['identity'],'call_id':row['call_id'],'entity_hash':row['entity_hash']}
            elif set(expr)=={'op','inputs'} and expr['op'] in {'add','subtract','multiply','divide'}:
                if not isinstance(expr['inputs'],list) or len(expr['inputs'])!=2:
                    raise EvidenceError('binary_operation_required')
                left,lk,ln=visit(expr['inputs'][0],depth+1);right,rk,rn=visit(expr['inputs'][1],depth+1)
                op=expr['op']
                if op in {'add','subtract'} and lk==rk and lk in {'money','ratio'}:
                    value=left+right if op=='add' else left-right;kind=lk
                elif op in {'multiply','divide'} and lk in {'money','ratio'} and rk=='ratio':
                    if op=='divide' and right==0:raise EvidenceError('division_by_zero')
                    value=left*right if op=='multiply' else left/right;kind=lk
                else:raise EvidenceError('incompatible_calculation_units')
                value=number(value,computed=True)
                if kind=='money' and value<0:raise EvidenceError('negative_money_result')
                proof={'operator':op,'inputs':[ln,rn],'type':kind,'value':str(value)}
            elif set(expr)=={'op','input','rounding'} and expr['op']=='round':
                value,kind,parent=visit(expr['input'],depth+1)
                modes={'half_even':ROUND_HALF_EVEN,'half_up':ROUND_HALF_UP}
                if kind!='money' or expr['rounding'] not in modes:raise EvidenceError('invalid_rounding_rule')
                value=value.quantize(quantum,rounding=modes[expr['rounding']])
                proof={'operator':'round','input':parent,'rounding':expr['rounding'],'type':kind,'value':str(value)}
            elif set(expr)=={'op','input','days'} and expr['op']=='date_add_days':
                original,kind,parent=visit(expr['input'],depth+1)
                if kind!='date' or type(expr['days']) is not int or abs(expr['days'])>3660:
                    raise EvidenceError('invalid_date_operation')
                value=(date.fromisoformat(original)+timedelta(days=expr['days'])).isoformat();kind='date'
                proof={'operator':'date_add_days','input':parent,'days':expr['days'],'type':kind,'value':value}
            else:raise EvidenceError('unknown_calculation_operator')
            node_id=object_hash({'task':self.task_id,'account':account,'proof':proof})
            nodes.append({'id':node_id,**proof})
            return value,kind,node_id
        try:
            with localcontext() as context:
                context.prec=40
                value,kind,node=visit(expression)
                if kind=='money' and value!=value.quantize(quantum):
                    raise EvidenceError('explicit_rounding_required')
        except (InvalidOperation,ZeroDivisionError,OverflowError,KeyError,TypeError,ValueError) as error:
            if isinstance(error,EvidenceError):raise
            raise EvidenceError('invalid_typed_calculation') from None
        return {'root':node,'type':kind,'value':value if kind in {'identifier','boolean'} else str(value),'unit':('account:'+account) if kind=='money' else kind,
                'scale':scale,'nodes':nodes,'sources':list(sources.values()),'task_authorized':False}

    def digest(self):
        return object_hash({'task_id':self.task_id,'records':self.records})
