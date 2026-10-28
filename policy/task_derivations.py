"""Bounded text/date transformations with receipts, never task authorization.

Only declared source fields enter this module. A parsed date or a calculation
does not authorize using it; the original request and exact call still need review.
"""
import re
from datetime import date, datetime, timedelta

from .argument_provenance import _calendar_dates

MAX_TEXT = 32_000
_CLOCK = re.compile(r'(?<![\w:])(?:(?P<h12>1[0-2]|0?[1-9])(?::(?P<m12>[0-5]\d))?\s*(?P<ampm>AM|PM)\b|(?P<h24>[01]?\d|2[0-3]):(?P<m24>[0-5]\d)(?![\w:]))', re.I)
_DURATION = re.compile(r'\b(?P<n>\d{1,3}|one|two|three|four|five|six|seven|eight|nine|ten)\s*-?\s*(?P<u>hours?|minutes?)\b', re.I)
_WORDS = dict(zip(('one','two','three','four','five','six','seven','eight','nine','ten'), range(1,11)))
_WEEKDAYS = {x:i for i,x in enumerate(('monday','tuesday','wednesday','thursday','friday','saturday','sunday'))}
_TIME_HINT=re.compile(r'\b(?:noon|midnight|morning|afternoon|evening|tonight|UTC|GMT|PST|PDT|EST|EDT|CET|CEST)\b|\bat\s+\d',re.I)


def validate_reminder_window(value):
    if value is None:return None
    if not isinstance(value,str) or not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d-(?:[01]\d|2[0-3]):[0-5]\d',value):
        raise ValueError('Reminder window must be HH:MM-HH:MM')
    start,end=value.split('-')
    if start>=end:raise ValueError('Reminder window must end later on the same day')
    return value


def reminder_instruction(window):
    if not window:return ''
    validate_reminder_window(window)
    return ('\nOperator calendar preference: for an explicitly requested reminder with an explicit '
            'calendar date and no time of day, use the local time window '+window+'. This preference '
            'supplies missing times only; it grants no operation, date, recipients or other effects. '
            'Preserve any user-specified time. A missing year requires the trusted simulation calendar year.\n')


def duration_candidates(request):
    if not isinstance(request,str) or len(request)>MAX_TEXT:
        return []
    values=[]
    for match in list(_DURATION.finditer(request))[:16]:
        raw=match['n'].lower(); n=_WORDS[raw] if raw in _WORDS else int(raw)
        minutes=n*(60 if match['u'].lower().startswith('hour') else 1)
        if 0<minutes<=7*24*60:
            values.append({'minutes':minutes,'user_span':[match.start(),match.end()]})
    return values


def datetime_candidates(text, *, reference_date=None):
    """Explicit dates/clocks, plus weekday/day anchored in the same native record.

    No wall clock, missing time defaults, cross-month inference or timezone
    conversion. Multiple candidates remain alternatives for semantic review.
    """
    if not isinstance(text,str) or len(text)>MAX_TEXT:
        return {}
    # Native calendar tools accept naive local times. Do not erase a stated zone.
    if re.search(r'\b(?:UTC|GMT|PST|PDT|EST|EDT|CST|CDT|CET|CEST|[A-Z]+/[A-Z]+)\b',text):
        return {}
    days=_calendar_dates(text)
    for m in list(re.finditer(r'(?<![\w-])\d{4}-\d{2}-\d{2}(?![\w-])',text))[:32]:
        try: d=date.fromisoformat(m.group())
        except ValueError: continue
        days[d.isoformat()]={'kind':'explicit_iso_date','spans':[[m.start(),m.end()]]}
    if reference_date:
        try: anchor=date.fromisoformat(reference_date)
        except (ValueError,TypeError): anchor=None
        if anchor:
            for m in list(re.finditer(r'\b('+'|'.join(_WEEKDAYS)+r')\s+(?:the\s+)?(\d{1,2})(?:st|nd|rd|th)\b',text,re.I))[:16]:
                try: d=anchor.replace(day=int(m[2]))
                except ValueError: continue
                if d.weekday()==_WEEKDAYS[m[1].lower()] and 0<=(d-anchor).days<=31:
                    days[d.isoformat()]={'kind':'record_month_weekday_day','spans':[[m.start(),m.end()]],
                                         'reference_date':reference_date}
    clocks=list(_CLOCK.finditer(text))[:32]
    if len(days)*len(clocks)>128:
        return {}
    result={}
    for day,proof in days.items():
        for m in clocks:
            a,b=proof['spans'][0]; gap=text[min(b,m.end()):max(a,m.start())]
            # Never borrow a clock from a different sentence/paragraph/date.
            if len(gap)>120 or re.search(r'[.!?\n]|\b(?:and|but|then)\b',gap,re.I): continue
            low,high=min(b,m.end()),max(a,m.start())
            if any(low<=other['spans'][0][0] and other['spans'][0][1]<=high
                   for other_day,other in days.items() if other_day!=day):continue
            if any(low<=other.start() and other.end()<=high for other in clocks if other is not m):continue
            if m['h12']:
                h=int(m['h12'])%12+(12 if m['ampm'].lower()=='pm' else 0); minute=int(m['m12'] or 0)
            else: h=int(m['h24']); minute=int(m['m24'])
            value=f'{day} {h:02d}:{minute:02d}'
            result[value]={'operator':'calendar_date_clock','date':proof,'clock_span':[m.start(),m.end()]}
    return result


def temporal_proposals(request, sources, start, end, *, reminder_window=None, current_day=None):
    """Prove normalization and end=start+user duration, without assigning authority."""
    proposals={}
    durations=duration_candidates(request)
    for row in [{'value':request,'origin':'user'}, *sources[:128]]:
        if row.get('origin')!='user' and row.get('label') not in {'business_text','document_text'}:
            continue
        context=row.get('context',{})
        reference=context.get('reference_date')
        # Record timestamps are context, never a default event time.
        if isinstance(reference,str): reference=reference[:10]
        for value,proof in datetime_candidates(row['value'],reference_date=reference).items():
            if value!=start: continue
            witness=({k:row[k] for k in ('call_id','path','result_hash')} if row.get('origin')!='user' else None)
            base={'candidate_origins':['DERIVED'],'source_verified':True,'task_authorized':False,
                  'authorization':'requires_per_call_review','transformation':'calendar_date_clock',
                  'derivation':proof}
            if witness:
                base.update(witness=witness,evidence_candidates=['obs:'+row['call_id']])
                if context: base['source_context']=context
            proposals.setdefault('start',base)
            for duration in durations:
                try: actual=(datetime.strptime(value,'%Y-%m-%d %H:%M')+timedelta(minutes=duration['minutes'])).strftime('%Y-%m-%d %H:%M')
                except (ValueError,OverflowError): continue
                if actual==end:
                    proposals.setdefault('end',{**base,'transformation':'datetime_add_minutes',
                        'derivation':{'operator':'datetime_add_minutes','start':value,'input':proof,**duration}})
    if (reminder_window and len(request)<=MAX_TEXT and re.search(r'\bremind(?:er)?\b',request,re.I)
            and not _CLOCK.search(request) and not _TIME_HINT.search(request)):
        validate_reminder_window(reminder_window)
        begin,finish=reminder_window.split('-')
        days=_calendar_dates(request)
        if current_day:
            from .context_bindings import resolve_dates
            for day in resolve_dates(request,current_day):
                days.setdefault(day,{'kind':'user_date_and_trusted_clock','reference_date':current_day})
        for match in re.finditer(r'(?<![\w-])\d{4}-\d{2}-\d{2}(?![\w-])',request):
            try:day=date.fromisoformat(match.group()).isoformat()
            except ValueError:continue
            days[day]={'spans':[[match.start(),match.end()]]}
        for day,evidence in days.items():
            if start==day+' '+begin and end==day+' '+finish:
                for kind in ('start','end'):
                    proposals.setdefault(kind,{'candidate_origins':['USER_DATE','OPERATOR_DEFAULT'],
                        'source_verified':True,'task_authorized':False,'authorization':'requires_per_call_review',
                        'transformation':'configured_reminder_window',
                        'derivation':{'date':day,'date_evidence':evidence,'window':reminder_window}})
    return proposals
