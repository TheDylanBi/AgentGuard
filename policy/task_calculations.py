"""Schema-declared native arithmetic and literal spans, never payment approval.

We construct a single expression from a supported phrase. We never enumerate
operators/literals looking for one that happens to equal the proposed amount.
New payees and payment dates cannot be supplied by this path.
"""
import copy
import re

from attestation.hashing import object_hash
from .argument_provenance import _span
from .resource_provenance import at
from .tool_contract import typed_equal
from .typed_evidence import EvidenceError, number

_NUMBER=r'(?P<value>\d{1,12}(?:\.\d{1,6})?)(?![\w/%+-]|\.(?!\s|$))'
_INCREASE=re.compile(r'\b(?:increase[ds]?|raise[ds]?)\s+(?:by\s+|of\s+)' + _NUMBER,re.I)


def validate_calculations(declaration, contract):
    rows=declaration.get('calculations',[])
    if not isinstance(rows,list) or len(rows)>4:
        raise ValueError('Invalid bounded calculation declaration')
    seen=set()
    for row in rows:
        if not isinstance(row,dict):raise ValueError('Invalid calculation declaration')
        operation=row.get('operation')
        required=({'parameter','label','field','key_parameter','operation'} if operation=='increase_by' else
                  {'parameter','label','field','payee_parameter','payee_field','operation'})
        if (set(row)!=required or operation not in {'increase_by','refund_difference','percentage_plus_fee'}
                or contract.fields.get(row['parameter'],{}).get('role')!='control'
                or any(not isinstance(row[k],str) or not row[k] for k in row)):
            raise ValueError('Calculations require a declared native record and bounded operator')
        if operation=='increase_by':
            binding=declaration.get('record_binding',{})
            if (contract.fields.get(row['key_parameter'],{}).get('role')!='resource'
                    or row['label']!=binding.get('label') or row['key_parameter']!=binding.get('key_parameter')
                    or binding.get('fields',{}).get(row['parameter'])!=row['field']):
                raise ValueError('Calculation input must be the same bound record field')
        elif contract.fields.get(row['payee_parameter'],{}).get('role')!='destination':
            raise ValueError('Payment arithmetic requires a native payee relation')
        identity=(row['parameter'],operation)
        if identity in seen:raise ValueError('Duplicate calculation operator')
        seen.add(identity)


def _increments(request, sources, state):
    candidates=[]
    if len(request)>32_000:return []
    inputs=[{'value':request,'origin':'user'}]
    # External literals must be from a task-named, observed native document
    # that still has exactly the same bytes in the current simulator namespace.
    for row in sources[:128]:
        binding=row.get('native_resource')
        if not binding or not isinstance(binding.get('key'),str) or not _span(request,binding['key']):continue
        try:
            current=at(state,binding['collection'])[binding['key']]
            if object_hash(current)!=binding['entity_hash']:continue
            if binding.get('namespace') and object_hash(at(state,binding['namespace']))!=binding.get('namespace_hash'):continue
        except (KeyError,ValueError,TypeError):continue
        inputs.append(row)
    for row in inputs:
        text=row.get('value')
        if not isinstance(text,str) or len(text)>32_000:continue
        for match in list(_INCREASE.finditer(text))[:8]:
            # Provenance only: negatives and conflicting instructions remain
            # visible to independent review; a number alone grants no permission.
            try: value=number(match['value'])
            except EvidenceError: continue
            literal={'value':str(value),'span':[match.start('value'),match.end('value')],
                     'phrase_span':[match.start(),match.end()], 'origin':row.get('origin','observed_document')}
            if row.get('origin')!='user':
                literal['witness']={k:row[k] for k in ('call_id','path','result_hash')}
                literal['native_resource']=row['native_resource']
            candidates.append(literal)
    # Re-reading the same document must not manufacture ambiguity or new rights.
    unique={object_hash({k:v for k,v in x.items() if k!='witness'}):x for x in candidates}
    return list(unique.values())


def propose_calculations(proof, declaration, arguments, graph, state, request, sources, *, equal_share_policy='explicit'):
    result=copy.deepcopy(proof)
    try:account=at(state,declaration['account'])
    except (KeyError,ValueError,TypeError):return result
    for cfg in declaration['calculations']:
        field=cfg['parameter'];operation=cfg['operation']
        if (field not in result['missing_fields'] or result.get('resource_failures')
                or result['fields'][field].get('kind')!='unproven'):continue
        rows=[r for r in graph.records.values() if r['account']==account and r['declaration']['label']==cfg['label']]
        if operation=='increase_by':
            key=arguments[cfg['key_parameter']]
            rows=[r for r in rows if typed_equal(r['entity'].get(r['declaration']['key']),key)]
            literals=_increments(request,sources,state)
            if len(literals)!=1:continue
            literal=literals[0]
        else:
            rows=[r for r in rows if typed_equal(r['entity'].get(cfg['payee_field']),arguments[cfg['payee_parameter']])
                  and r['declaration']['fields'].get(cfg['payee_field'])=='account']
            literal=_user_formula(request,operation,equal_share_policy=equal_share_policy)
            if literal is None:continue
        if len(rows)!=1:continue
        row=rows[0];key=row['entity'][row['declaration']['key']]
        native={'source':{'label':cfg['label'],'key':key,'field':cfg['field']}}
        if operation=='increase_by':
            expr={'op':'add','inputs':[native,{'literal':literal['value'],'type':'money'}]}
        elif operation=='refund_difference':
            half={'op':'divide','inputs':[{'literal':literal['total'],'type':'money'},{'literal':2,'type':'ratio'}]}
            expr={'op':'subtract','inputs':[native,half]}
        else:
            ratio={'op':'divide','inputs':[{'literal':literal['percent'],'type':'ratio'},{'literal':100,'type':'ratio'}]}
            expr={'op':'add','inputs':[{'op':'multiply','inputs':[native,ratio]},
                                      {'literal':literal['fee'],'type':'money'}]}
        try:
            calc=graph.evaluate(expr,state=state,account=account,scale=rows[0]['declaration']['scale'])
            if type(arguments[field]) not in (int,float,str) or number(arguments[field])!=number(calc['value']):continue
        except (EvidenceError,KeyError,TypeError,ValueError):continue
        # The expression and constants come from the closed phrase grammar,
        # never an expression supplied by action/tool text or answer matching.
        for node in calc['nodes']:
            if node['operator']=='trusted_contract_literal':
                node.update(operator='task_text_literal',literal_evidence=copy.deepcopy(literal))
        remap={}
        for node in calc['nodes']:
            old=node.pop('id')
            if 'inputs' in node:node['inputs']=[remap[x] for x in node['inputs']]
            if 'input' in node:node['input']=remap[node['input']]
            node['id']=object_hash({'task':graph.task_id,'account':account,'proof':node})
            remap[old]=node['id']
        calc['root']=remap[calc['root']]
        witnesses=[{k:node[k] for k in ('call_id','path','result_hash')}
                   for node in calc['nodes'] if node['operator']=='native_field']
        if literal.get('witness'):witnesses.append(literal['witness'])
        result['fields'][field]={'kind':'typed_calculation','transformation':operation,
            'calculation':calc,'literal_evidence':literal,'witnesses':witnesses,
            'source_verified':True,'task_authorized':False}
        if operation!='increase_by':
            payee=cfg['payee_parameter']
            if result['fields'][payee].get('kind')=='unproven':
                try:
                    identity=graph.evaluate({'source':{'label':cfg['label'],'key':key,'field':cfg['payee_field']}},
                                            state=state,account=account,scale=row['declaration']['scale'])
                except EvidenceError:continue
                result['fields'][payee]={'kind':'typed_native_field','transformation':'EXACT_EXTRACT',
                    'calculation':identity,'witnesses':[witnesses[0]],'task_authorized':False}
    return result


def _user_formula(request,operation,*,equal_share_policy='explicit'):
    if not isinstance(request,str) or len(request)>32_000:return None
    if operation=='refund_difference':
        # Half must be explicit, or supplied by the separately configured
        # two-party convention. Text alone cannot establish that convention.
        half=bool(re.search(r'\bhalf\b',request,re.I))
        two_party=(equal_share_policy=='two-party' and re.search(r'\bwith a friend\b',request,re.I)
                   and re.search(r'\btheir share\b',request,re.I) and re.search(r'\bwe spent\b',request,re.I)
                   and not re.search(r'\b(?:unequal|different|percent|third|three|four|other friends)\b|%',request,re.I))
        if not half and not two_party:return None
        matches=list(re.finditer(r'\b(?:spent|total(?:\s+(?:of|was|is))?)\s+'+_NUMBER,request,re.I))
        if len(matches)!=1:return None
        match=matches[0]
        return {'origin':'user','grammar':operation,'total':match['value'],
                'span':[match.start('value'),match.end('value')],
                'division':'explicit_half' if half else 'configured_two_party_equal_share'}
    rates=list(re.finditer(r'(?<![\w.])(?P<value>\d{1,3}(?:\.\d{1,6})?)\s*%\s+of\b',request,re.I))
    fees=list(re.finditer(r'\bfee\s+of\s+'+_NUMBER,request,re.I))
    if len(rates)!=1 or len(fees)!=1:return None
    rate,fee=rates[0],fees[0]
    return {'origin':'user','grammar':operation,'percent':rate['value'],'fee':fee['value'],
            'spans':[[rate.start(),rate.end()],[fee.start(),fee.end()]],'percentage_unit':100}


def propose_document_payment(proof,declaration,arguments,state,request,sources):
    """A task-named native bill can supply labelled fields, never task authority."""
    cfg=declaration.get('document_payment')
    if not cfg or len(request)>32_000:return proof
    candidates=[]
    for row in sources[:128]:
        binding=row.get('native_resource');text=row.get('value')
        if (row.get('label') not in {'document_text','business_text'} or not binding or not isinstance(text,str) or len(text)>32_000
                or not isinstance(binding.get('key'),str) or not _span(request,binding['key'])):continue
        try:
            if object_hash(at(state,binding['collection'])[binding['key']])!=binding['entity_hash']:continue
            if (binding.get('namespace')!=declaration['account']
                    or object_hash(at(state,declaration['account']))!=binding.get('namespace_hash')):continue
        except (KeyError,ValueError,TypeError):continue
        totals=list(re.finditer(r'^\s*Total\s+(\d{1,12}(?:\.\d{1,2})?)\s*$',text,re.M|re.I))
        accounts=list(re.finditer(r'^\s*IBAN:\s*([A-Z]{2}\d{2}[A-Z0-9]{10,30})\s*$',text,re.M))
        if len(totals)!=1 or len(accounts)!=1:continue
        amount,recipient=totals[0],accounts[0]
        if number(amount[1])<=0:continue
        candidates.append((row,amount,recipient))
    # Re-reading identical data is not a new bill or a new payment entitlement.
    candidates=list({object_hash(x[0]['native_resource']):x for x in candidates}.values())
    if len(candidates)!=1:return proof
    row,amount,recipient=candidates[0];result=copy.deepcopy(proof)
    for parameter,match in ((cfg['amount_parameter'],amount),(cfg['recipient_parameter'],recipient)):
        if parameter not in result['missing_fields']:continue
        actual=arguments[parameter]
        try:equal=number(actual)==number(match[1]) if parameter==cfg['amount_parameter'] else typed_equal(actual,match[1])
        except (EvidenceError,TypeError):continue
        if not equal:continue
        result['fields'][parameter]={'kind':'native_document_field','source_verified':True,'task_authorized':False,
            'transformation':'labelled_bill_field','native_resource':row['native_resource'],
            'source_id':object_hash({'account':at(state,declaration['account']),'document':row['native_resource']}),
            'span':[match.start(1),match.end(1)],'witnesses':[{k:row[k] for k in ('call_id','path','result_hash')}]}
    return result
