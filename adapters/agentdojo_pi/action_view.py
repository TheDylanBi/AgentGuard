"""Declared inventory views reduce action context; native host results stay intact."""
import json
from policy.runtime_bindings import json_value


def validate_action_view(spec,tools):
    view=spec.get('action_result_view')
    if view is None:return
    if (not spec.get('schema_hash') or not isinstance(view,dict)
            or set(view)!={'fields','detail_tool','detail_parameter'}
            or not isinstance(view['fields'],list) or not 1<=len(view['fields'])<=12
            or any(not isinstance(x,str) or not x for x in view['fields'])
            or len(set(view['fields']))!=len(view['fields'])
            or view['detail_tool'] not in tools
            or spec.get('semantic_action',{}).get('operation')!='list'
            or not isinstance(view['detail_parameter'],str) or not view['detail_parameter']
            or view['detail_parameter'] not in tools[view['detail_tool']].get('parameter_roles',{})
            or not set(tools[view['detail_tool']].get('semantic_action',{}).get('effects',[]))<={'read','filesystem_read'}):
        raise ValueError('Invalid declared inventory view')


def action_view(value,spec):
    view=spec.get('action_result_view')
    if not view:return None
    rows=json_value(value)
    if not isinstance(rows,list) or any(not isinstance(x,dict) for x in rows):
        raise ValueError('Inventory result differs from declared list view')
    return json.dumps({'view':'inventory_metadata','items':[{k:r[k] for k in view['fields'] if k in r} for r in rows],
        'content_omitted':True,'read_content_with':{'tool':view['detail_tool'],'parameter':view['detail_parameter']},
        'meaning':'All inventory rows retained. Read the selected resource for full content; this view grants no permission.'},
        ensure_ascii=False,separators=(',',':'))


def resource_catalog_view(catalog):
    """Opaque references resolve identically; host hashes/receipts stay in audit."""
    return {'protocol':catalog['protocol'],'resources':[
        {k:row[k] for k in ('argument','label','preview')} for row in catalog['resources']],
        'truncated':catalog['truncated'],'new_permissions':False,'whole_task_verified':False}


def feedback_view(feedback):
    # Keep every actual requirement, decision, recovery instruction and stop
    # signal. Full observation IDs already exist in the original tool history
    # and reviewer packet; repeating this growing list supplies no new fact.
    return {k:v for k,v in feedback.items() if k!='existing_observation_refs'}
