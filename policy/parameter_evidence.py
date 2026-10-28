"""Exact typed field delegation, not inferred financial authorization.

Schema-pinned declarations select native fields and bounded calculations. Parsed
literal candidates never become payment authorization or new payee identities.
"""
import copy

from .resource_provenance import at
from .tool_contract import typed_equal
from .typed_evidence import EvidenceError, number


def validate_parameter_evidence(spec, contract):
    declaration = spec.get('parameter_evidence')
    if declaration is None:
        return
    if (not spec.get('schema_hash') or not isinstance(declaration, dict)
            or not {'account', 'fields', 'descriptive_fields', 'reason'} <= set(declaration)
            or set(declaration) - {'account', 'fields', 'descriptive_fields', 'reason', 'record_binding','calculations','execution_date_parameter','document_payment'}
            or not isinstance(declaration['account'], list) or not 1 <= len(declaration['account']) <= 12
            or any(not isinstance(x, str) or not x for x in declaration['account'])
            or not isinstance(declaration['fields'], dict) or not declaration['fields'] and not declaration.get('record_binding')
            or not isinstance(declaration['descriptive_fields'], list)
            or not isinstance(declaration['reason'], str) or not declaration['reason'].strip()):
        raise ValueError('Invalid typed parameter evidence declaration')
    from .task_calculations import validate_calculations
    validate_calculations(declaration,contract)
    execution_date=declaration.get('execution_date_parameter')
    if execution_date is not None and (not isinstance(execution_date,str) or contract.fields.get(execution_date,{}).get('role')!='control'
            or spec.get('semantic_action',{}).get('operation')!='send'
            or spec.get('capability',{}).get('financial_transfer')!='allowed'):
        raise ValueError('Execution date preference requires a declared immediate transfer control')
    document=declaration.get('document_payment')
    if document is not None and (not isinstance(document,dict) or set(document)!={'amount_parameter','recipient_parameter'}
            or any(not isinstance(value,str) or not value for value in document.values())
            or contract.fields.get(document.get('amount_parameter'),{}).get('role')!='control'
            or contract.fields.get(document.get('recipient_parameter'),{}).get('role')!='destination'
            or not execution_date):raise ValueError('Bill projection requires declared transfer fields')
    record = declaration.get('record_binding')
    if record is not None:
        if (not isinstance(record, dict) or set(record) != {'label', 'key_parameter', 'fields'}
                or not isinstance(record['label'], str) or not record['label']
                or record['key_parameter'] not in contract.fields
                or contract.fields[record['key_parameter']]['role'] != 'resource'
                or not isinstance(record['fields'], dict) or not record['fields']
                or any(field not in contract.fields or contract.fields[field]['role'] == 'execution'
                       or not isinstance(native, str) or not native for field,native in record['fields'].items())
                or record['key_parameter'] not in record['fields']
                or set(record['fields']) & set(declaration['fields'])
                or spec.get('semantic_action',{}).get('operation') != 'update'
                or spec.get('target_field') != record['key_parameter']):
            raise ValueError('Record parameter binding requires a declared native resource key')
    for field, source in declaration['fields'].items():
        if (field not in contract.fields or contract.fields[field]['role'] not in {'destination', 'control'}
                or not isinstance(source, dict) or not {'label', 'field', 'type'} <= set(source)
                or set(source) - {'label', 'field', 'type', 'where_parameters'}
                or any(not isinstance(source[x], str) or not source[x] for x in ('label','field','type'))
                or source['type'] not in {'money', 'account', 'date'}
                or contract.fields[field]['role'] == 'destination' and source['type'] != 'account'):
            raise ValueError('Typed evidence requires explicit field types and roles')
        relations=source.get('where_parameters',{})
        if (not isinstance(relations,dict) or len(relations)>8
                or any(not isinstance(native,str) or not native or not isinstance(param,str)
                       or param not in contract.fields or contract.fields[param]['role']!='destination'
                       for native,param in relations.items())):
            raise ValueError('Native business selectors require declared destination fields')
    if (any(not isinstance(field,str) for field in declaration['descriptive_fields'])
            or len(set(declaration['descriptive_fields'])) != len(declaration['descriptive_fields'])
            or any(field not in contract.fields or contract.fields[field]['role'] != 'content'
                   for field in declaration['descriptive_fields'])
            or any(spec['capability'].get(flag) == 'allowed' for flag in ('process', 'credential', 'credential_access'))):
        raise ValueError('Descriptive evidence cannot cover execution or control parameters')


def propose_parameter_evidence(proof, spec, arguments, graph, state, *, request='', sources=(),equal_share_policy='explicit'):
    """Project unique, fresh native values; authorization remains per-call review.

    A matching amount in several transactions is ambiguous. Native account fields
    establish correspondence, not that this is the user's intended payee.
    """
    declaration = spec.get('parameter_evidence')
    if not declaration:
        return proof
    result = copy.deepcopy(proof)
    def missing_account():
        record=declaration.get('record_binding')
        if record:
            result.setdefault('resource_failures',{})[record['key_parameter']]='source_unresolved'
            result['review_ready']=False
        return result
    try:
        account = at(state, declaration['account'])
    except (KeyError, TypeError, ValueError):
        return missing_account()
    if not isinstance(account, str) or not account:
        return missing_account()
    pending = result.setdefault('data_use_pending', {})
    record = declaration.get('record_binding')
    if record is not None:
        key = arguments[record['key_parameter']]
        key_verified = False
        # Source lookup is bounded by a single observed native key, NOT a text
        # mention or a model's asserted record. Each field rechecks freshness,
        # uniqueness, namespace and the current complete record through the DAG.
        matches = [row for row in graph.records.values() if row['account'] == account
                   and row['declaration']['label'] == record['label']
                   and typed_equal(row['entity'].get(row['declaration']['key']), key)]
        if len(matches) == 1:
            row = matches[0]
            for field,native in record['fields'].items():
                if field not in result['missing_fields'] and field != record['key_parameter']:
                    continue
                if native == row['declaration']['key'] and field != record['key_parameter']:
                    continue
                expression = {'source': {'label': record['label'], 'key': key, 'field': native}}
                try:
                    calculation = graph.evaluate(expression, state=state, account=account,
                                                 scale=row['declaration']['scale'])
                    kind = calculation['type'];actual = arguments[field]
                    role = spec.get('parameter_roles',{}).get(field,{}).get('role')
                    if (field == record['key_parameter'] and kind != 'identifier'
                            or role == 'destination' and kind != 'account'):
                        continue
                    equal = (type(actual) in (int,float,str) and number(actual)==number(calculation['value'])
                             if kind == 'money' else typed_equal(actual,calculation['value']))
                    if not equal:continue
                    root = next(n for n in calculation['nodes'] if n['id'] == calculation['root'])
                    result['fields'][field] = {'kind':'typed_native_field', 'task_authorized':False,
                        'transformation':'NATIVE_RECORD_ID' if field==record['key_parameter'] else 'PRESERVE_NATIVE_FIELD',
                        'record_key_parameter':record['key_parameter'], 'record_key':key,
                        'calculation':calculation,
                        'witnesses':[{k:root[k] for k in ('call_id','path','result_hash')}]}
                    if field == record['key_parameter']:
                        key_verified = True
                except (EvidenceError,KeyError,TypeError,ValueError):
                    continue
        if not key_verified:
            # A declared record identity is mandatory even before any tool has
            # tainted the task. A semantic allow cannot manufacture this receipt.
            result.setdefault('resource_failures', {}).setdefault(record['key_parameter'], 'source_unresolved')
    for field, selector in declaration['fields'].items():
        if field not in result['missing_fields']:
            continue
        matches = []
        for row in graph.records.values():
            decl = row['declaration']
            if (row['account'] != account or decl['label'] != selector['label']
                    or decl['fields'].get(selector['field']) != selector['type']):
                continue
            expression = {'source': {'label': decl['label'], 'key': row['entity'][decl['key']],
                                     'field': selector['field']}}
            relations=selector.get('where_parameters',{})
            if any(decl['fields'].get(native) != 'account' for native in relations):
                continue
            if relations:
                expression['source']['where']={native:arguments[param] for native,param in relations.items()}
            try:
                calculation = graph.evaluate(expression, state=state, account=account, scale=decl['scale'])
                actual = arguments[field]
                equal = (type(actual) in (int, float, str) and number(actual) == number(calculation['value'])
                         if selector['type'] == 'money' else typed_equal(actual, calculation['value']))
                if equal:
                    root = next(node for node in calculation['nodes'] if node['id'] == calculation['root'])
                    matches.append({'calculation': calculation, 'call_id': root['call_id'],
                                    'path': root['path'], 'result_hash': root['result_hash']})
            except (EvidenceError, KeyError, TypeError, ValueError):
                continue
        if len(matches) == 1:
            match = matches[0]
            result['fields'][field] = {'kind': 'typed_native_field', 'task_authorized': False,
                'transformation': 'EXACT_EXTRACT', 'calculation': match['calculation'],
                'business_selector':{native:arguments[param] for native,param in selector.get('where_parameters',{}).items()},
                'witnesses': [{k: match[k] for k in ('call_id', 'path', 'result_hash')}]}
    if declaration.get('calculations'):
        from .task_calculations import propose_calculations
        result=propose_calculations(result,declaration,arguments,graph,state,request,list(sources),equal_share_policy=equal_share_policy)
        pending=result.setdefault('data_use_pending',{})
    if declaration.get('document_payment'):
        from .task_calculations import propose_document_payment
        result=propose_document_payment(result,declaration,arguments,state,request,list(sources))
        pending=result.setdefault('data_use_pending',{})
    # Only explicitly declared non-executable description fields can be generated.
    for field in declaration['descriptive_fields']:
        if field in result['missing_fields'] and isinstance(arguments[field], str) and len(arguments[field]) <= 4096:
            pending[field] = {'candidate_origins': ['AGENT_GENERATED_DESCRIPTION'],
                'source_verified': False, 'task_authorized': False,
                'authorization': 'requires_per_call_review'}
    result['missing_fields'] = [field for field, evidence in result['fields'].items()
                                if evidence.get('kind') == 'unproven']
    result['complete'] = not result['missing_fields']
    result['review_ready'] = not result.get('resource_failures') and all(
        field in pending for field in result['missing_fields'])
    return result
