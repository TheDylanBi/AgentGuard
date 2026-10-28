"""Schema-bound data-use proposals, never source proofs or execution grants.

Local generated text may require semantic authorization without literal origin.
Network data use needs a separately acknowledged, exact per-call flow scope.
Execution and financial derivations are excluded from this semantic path.
"""
import copy
import re
from attestation.hashing import object_hash


def validate_data_use(spec, contract):
    declaration = spec.get('review_data_use')
    if declaration is None:
        return
    if (not spec.get('schema_hash') or not isinstance(declaration, dict)
            or not {'content_fields', 'semantic_resources', 'reason'} <= set(declaration)
            or set(declaration)-{'content_fields','semantic_resources','reason','flow_review','control_fields','url_fields','new_identity_fields','temporal_derivations'}
            or not isinstance(declaration['content_fields'], list)
            or any(not isinstance(x, str) for x in declaration['content_fields'])
            or len(set(declaration['content_fields'])) != len(declaration['content_fields'])
            or type(declaration['semantic_resources']) is not bool
            or not isinstance(declaration['reason'], str) or not declaration['reason'].strip()):
        raise ValueError('Invalid reviewed data-use declaration')
    caps = spec['capability']
    flow = declaration.get('flow_review',False)
    if type(flow) is not bool:
        raise ValueError('Invalid flow review declaration')
    controls = declaration.get('control_fields',{})
    urls = declaration.get('url_fields',[])
    new_ids=declaration.get('new_identity_fields',[])
    if (not isinstance(new_ids,list) or len(set(new_ids))!=len(new_ids)
            or any(field not in contract.fields or contract.fields[field]['role']!='resource'
                or field!=spec.get('target_field') or field in spec.get('resource_parameters',{})
                or field in spec.get('identity_scopes',{}) for field in new_ids)
            or new_ids and (not flow or spec.get('semantic_action',{}).get('operation')!='create')):
        raise ValueError('New identities require a declared create target and flow review')
    if not isinstance(controls,dict) or not isinstance(urls,list):
        raise ValueError('Invalid role-based data-use declaration')
    def finite_configuration(field):
        schema=contract.schema['properties'][field]
        reference=schema.get('$ref','')
        if reference.startswith('#/$defs/'):
            schema=contract.schema.get('$defs',{}).get(reference.split('/')[-1],{})
        return bool(schema.get('enum'))
    for field,kind in controls.items():
        if (field not in contract.fields or contract.fields[field]['role'] != 'control'
                or kind not in {'derived_text','configuration'}
                or kind == 'configuration' and not finite_configuration(field)):
            raise ValueError('Only reviewed control/configuration fields can enter semantic review')
    temporal=declaration.get('temporal_derivations')
    if temporal is not None and (not isinstance(temporal,dict) or set(temporal)!={'start','end'}
            or len(set(temporal.values()))!=2
            or any(not isinstance(x,str) or controls.get(x)!='derived_text' for x in temporal.values())
            or not flow or spec.get('semantic_action',{}).get('operation') not in {'create','update'}):
        raise ValueError('Temporal derivations require declared start/end controls and flow review')
    if any(field not in contract.fields or contract.fields[field]['role'] != 'destination' for field in urls):
        raise ValueError('URL normalization requires declared destination fields')
    if (flow or controls or urls) and (caps.get('process') == 'allowed'
            or caps.get('credential_access') == 'allowed' or caps.get('credential') == 'allowed'
            or caps.get('financial_transfer') == 'allowed' or caps.get('effect_type') == 'financial_transfer'):
        raise ValueError('Semantic data use cannot authorize executable or financial derivations')
    if declaration['content_fields'] and (
            any(caps.get(k) == 'allowed' for k in ('process','credential_access','credential'))
            or not flow and (any(caps.get(k) == 'allowed' for k in ('external_share','network','network_egress'))
                             or caps.get('effect_type') not in {'data_mutation', None})
            or spec.get('semantic_action', {}).get('operation') not in {'create', 'append', 'update', 'send'}):
        raise ValueError('Generated content review requires a bounded local mutation')
    for field in declaration['content_fields']:
        if field not in contract.fields or contract.fields[field]['role'] != 'content':
            raise ValueError('Data-use review cannot supply identity, control or destination values')


def propose_data_use(proof, spec, arguments, *, request, sources=(), reminder_window=None, current_day=None):
    """Mark semantic work explicitly; keep source completeness false when unknown."""
    result = copy.deepcopy(proof)
    declaration = spec.get('review_data_use', {})
    pending = {}
    # A failed bounded original-request analysis cannot be upgraded by this path.
    if len(request) <= 32_000:
        from .argument_provenance import _span
        temporal=declaration.get('temporal_derivations')
        if temporal:
            from .task_derivations import temporal_proposals
            proposed=temporal_proposals(request,list(sources),arguments[temporal['start']],arguments[temporal['end']],
                                        reminder_window=reminder_window,current_day=current_day)
            for kind,field in temporal.items():
                if field in result['missing_fields'] and kind in proposed:
                    pending[field]=proposed[kind]
            # A move may preserve the duration of the same freshly bound event.
            # Its new start must first have a literal/verified derivation. The
            # receipt proves correspondence only; target selection stays reviewed.
            from datetime import datetime
            for field,derivation in spec.get('resource_derivations',{}).items():
                binding=result.get('resource_bindings',{}).get(derivation['resource_parameter'])
                begin=derivation['new_start']
                if field not in result['missing_fields'] or not binding or (begin in result['missing_fields'] and begin not in pending):continue
                try:
                    duration=(datetime.fromisoformat(binding['attributes'][derivation['end_field']])
                              -datetime.fromisoformat(binding['attributes'][derivation['start_field']]))
                    if (0<duration.total_seconds()<=7*86400 and arguments[field] is not None
                            and datetime.fromisoformat(arguments[field])==datetime.fromisoformat(arguments[begin])+duration):
                        pending[field]={'candidate_origins':['DERIVED'],'source_verified':True,
                            'task_authorized':False,'authorization':'requires_per_call_review',
                            'transformation':'preserve_resource_duration','duration_seconds':duration.total_seconds(),
                            'evidence_candidates':['obs:'+binding['call_id']]}
                except (ValueError,TypeError,KeyError,OverflowError):pass
        for field in declaration.get('new_identity_fields',[]):
            value=arguments[field]
            if field not in result['missing_fields'] or not isinstance(value,str):continue
            witnesses=[row for row in sources if row['label'] in {'business_text','document_text'}
                       and _span(row['value'],value)]
            if witnesses:
                pending[field]={'candidate_origins':['TOOL_OBSERVED_NEW_IDENTITY'],
                    'source_verified':True,'identity_verified':False,'task_authorized':False,
                    'authorization':'requires_per_call_review',
                    'evidence_candidates':sorted({'obs:'+row['call_id'] for row in witnesses})}
        for field in declaration.get('url_fields',[]):
            value=arguments[field]
            if field in result['missing_fields'] and isinstance(value,str):
                bare=value.removeprefix('https://').removeprefix('http://')
                span=_span(request,bare)
                if span:
                    result['fields'][field]={'kind':'user_url_key','user_witness':span,
                        'transformation':'strip_http_scheme','task_authorized':False}
                else:
                    from .delegation import url_boundary_candidate
                    candidate=url_boundary_candidate(request,value)
                    if candidate:pending[field]=candidate
        for field,kind in declaration.get('control_fields',{}).items():
            if field not in result['missing_fields'] or field in pending:
                continue
            value=arguments[field]
            if kind=='configuration':
                pending[field]={'candidate_origins':['CONFIGURATION'],'source_verified':False,
                                'task_authorized':False,'authorization':'requires_per_call_review'}
            elif isinstance(value,str) and sources:
                temporal=(spec.get('semantic_action',{}).get('operation') in {'create','update','append','send','share','execute'}
                          and bool(re.fullmatch(r'\d{4}-\d{2}-\d{2}(?:[T ]\d.*)?',value)))
                matching=[row for row in sources if _span(row['value'],value)] if temporal else sources
                if not matching:continue
                # Exact occurrence supplies a candidate, not authority to use
                # a document's time. Unrelated reads cannot invent defaults.
                pending[field]={'candidate_origins':['DERIVED'],'source_verified':False,
                    'task_authorized':False,'authorization':'requires_per_call_review',
                    'evidence_candidates':sorted({'obs:'+row['call_id'] for row in matching})}
                if temporal:pending[field]['transformation']='exact_temporal_candidate'
        for field in declaration.get('content_fields', []):
            if field in result['missing_fields'] and isinstance(arguments[field], str):
                pending[field] = {'candidate_origins': ['DERIVED', 'AGENT_GENERATED'],
                    'source_verified': False, 'task_authorized': False,
                    'integrity': 'untrusted_candidate', 'authorization': 'requires_per_call_review'}
                text = arguments[field]
                lines = [line.strip().removeprefix('- ').strip() for line in text.splitlines() if line.strip()]
                for source in sources:
                    if source['label'] != 'document_text':
                        continue
                    original = source['value']
                    source_lines = {line.strip().removeprefix('- ').strip()
                                    for line in original.splitlines() if line.strip()}
                    operation = ('exact_copy' if text == original else
                                 'line_projection' if lines and all(line in source_lines for line in lines) else None)
                    if operation:
                        pending[field].update(candidate_origins=['DERIVED'],
                            source_verified=True, transformation=operation,
                            witness={'call_id': source['call_id'], 'path': source['path'],
                                     'result_hash': source['result_hash'], 'value_hash': object_hash(text)})
                        # This proves correspondence, not that these are the
                        # requested lines, nor that the destination is permitted.
                        break
    result['data_use_pending'] = pending
    result['missing_fields']=[field for field,evidence in result['fields'].items() if evidence.get('kind')=='unproven']
    result['complete']=not result['missing_fields']
    result['review_ready'] = not result.get('resource_failures') and all(
        field in pending for field in result['missing_fields'])
    return result
