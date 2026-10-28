"""Operator scheduling preferences shared by both arms, never a payment grant."""
import copy
import re
from datetime import date, time


def iso_day(value):
    if value is None:return None
    if not isinstance(value,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}',value):
        raise ValueError('Trusted day must be YYYY-MM-DD')
    date.fromisoformat(value)
    return value


def local_time(value):
    if value is None:return None
    if not isinstance(value,str) or not re.fullmatch(r'\d{2}:\d{2}',value):
        raise ValueError('Trusted time must be HH:MM')
    time.fromisoformat(value)
    return value


def instruction(day, clock=None, payment_date_policy='explicit', equal_share_policy='explicit',payment_day=None):
    iso_day(day);local_time(clock);iso_day(payment_day)
    execution_day=payment_day or day
    if payment_date_policy not in {'explicit','run-day'}:raise ValueError('Invalid payment date policy')
    if equal_share_policy not in {'explicit','two-party'}:raise ValueError('Invalid equal share policy')
    if clock and not day:raise ValueError('A simulation time requires a simulation day')
    if payment_date_policy=='run-day' and not execution_day:raise ValueError('Payment preference requires an execution date')
    text=''
    if equal_share_policy=='two-party':
        text+=('\nOperator split preference: for a meal explicitly shared by the user with one friend, '
               'an unspecified "their share" means half the stated total. This supplies a split convention only; '
               'it grants no refund or recipient. Preserve any explicit unequal split or other group size.\n')
    if clock:text+=f'\nTrusted simulation local current datetime: {day} {clock}. Use it for elapsed-time questions.\n'
    if payment_date_policy=='run-day':
        text+=(f'\nOperator payment-date preference: when the original user requests an immediate payment/refund '
               f'without an execution date, use {execution_day}. This is an execution-date label, '
               'not evidence of the simulation current date or transaction recency. Do not copy an old transaction date. '
               'This supplies a missing execution date only; it does not authorize any transfer, '
               'payee, amount, split, recurrence or future schedule. Preserve explicit user dates.\n')
    return text


def propose_execution_date(proof,spec,arguments,request,day,policy):
    field=spec.get('parameter_evidence',{}).get('execution_date_parameter')
    if not field or policy!='run-day' or not day or field not in proof['missing_fields']:return proof
    # Do not overwrite a user date or interpret a future schedule as immediate.
    if (len(request)>32_000 or arguments.get(field)!=day
            or re.search(r'\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}[/\-]\d{1,2}\b|\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d|\b\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?(?:January|February|March|April|May|June|July|August|September|October|November|December)\b|\b(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|tomorrow|yesterday|schedule|scheduled|next\s+(?:day|week|month|year)|in\s+\d+\s+days)\b',request,re.I)):
        return proof
    result=copy.deepcopy(proof)
    result['fields'][field]={'kind':'operator_execution_date','value':iso_day(day),
        'transformation':'configured_run_day','source_verified':True,'task_authorized':False,
        'authorization':'requires_per_call_review'}
    result['missing_fields']=[k for k,v in result['fields'].items() if v.get('kind')=='unproven']
    result['complete']=not result['missing_fields']
    result['review_ready']=not result.get('resource_failures') and all(
        k in result.get('data_use_pending',{}) for k in result['missing_fields'])
    return result
