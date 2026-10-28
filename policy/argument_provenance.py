"""Bounded, deterministic source witnesses; never task authorization.

Only the immutable user text and operator-reviewed no-effect values are trusted
sources here. A matching span proves occurrence, not the user's intended use.
The independent reviewer must still check context, conditions and destinations.
Tool observations and model explanations can never extend this source set.
"""
import re
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation

from attestation.hashing import object_hash
from .tool_contract import typed_equal

MAX_TEXT = 32_000
MAX_NODES = 256


def _span(text, value):
    if not value or len(value) > 8_000:
        return None
    # Prevent an address/path/number fragment from inheriting a larger token's
    # provenance. This remains a source witness, NOT a semantic permission.
    for match in re.finditer(re.escape(value), text):
        before = text[match.start()-1:match.start()] if match.start() else ''
        after = text[match.end():match.end()+1]
        if after == '.' and (match.end()+1 == len(text) or text[match.end()+1].isspace()):
            after = ''  # Sentence punctuation, never an address domain suffix.
        extra = '@_/-' + ('.+%' if ('@' in value or '/' in value or '\\' in value
                                     or '.' in value and not any(c.isspace() for c in value)) else '')
        token = lambda c: bool(c and (c.isalnum() or c in extra))
        if not token(before) and not token(after):
            return {'kind': 'user_span', 'span': [match.start(), match.end()]}
    return None


def _datetimes(text):
    """Small explicit ISO-date/clock + duration algebra, with source spans.

    No relative dates, time zones, fuzzy names, external values or arbitrary
    model-specified expressions. Cross-combinations need semantic review.
    """
    dates = list(re.finditer(r'(?<![\w-])\d{4}-\d{2}-\d{2}(?![\w-])', text))
    clocks = list(re.finditer(r'(?<![\w:])(?:[01]?\d|2[0-3]):[0-5]\d(?![\w:])', text))
    durations = list(re.finditer(r'\b(\d{1,3}|one|two|three|four)\s*-?\s*(hours?|minutes?)\b', text, re.I))
    if len(dates) * len(clocks) * (1 + len(durations)) > 128:
        return {}
    result = {}
    words = {'one': 1, 'two': 2, 'three': 3, 'four': 4}
    for date in dates:
        for clock in clocks:
            try:
                start = datetime.strptime(date.group() + ' ' + clock.group(), '%Y-%m-%d %H:%M')
            except ValueError:
                continue
            spans = [[date.start(), date.end()], [clock.start(), clock.end()]]
            result.setdefault(start.strftime('%Y-%m-%d %H:%M'), {
                'kind': 'iso_date_clock', 'spans': spans})
            for duration in durations:
                raw = duration.group(1).lower()
                count = words[raw] if raw in words else int(raw)
                minutes = count * (60 if duration.group(2).lower().startswith('hour') else 1)
                if not 0 < minutes <= 7 * 24 * 60:
                    continue
                try:
                    end = start + timedelta(minutes=minutes)
                except OverflowError:
                    continue
                result.setdefault(end.strftime('%Y-%m-%d %H:%M'), {
                    'kind': 'datetime_add_minutes', 'minutes': minutes,
                    'spans': spans + [[duration.start(), duration.end()]]})
    return result


def _calendar_dates(text):
    """Explicit English month dates/ranges with a stated year; no defaults.

    Produces date candidates, not start/end assignments or task permission.
    Ambiguous cross-year ranges never acquire an inferred year.
    """
    months={name.lower():index for index,name in enumerate((
        'January','February','March','April','May','June','July','August','September','October','November','December'),1)}
    month='(?:'+'|'.join(months)+')';day=r'\d{1,2}(?:st|nd|rd|th)?'
    result={}
    def add(m,d,y,match,kind):
        try:
            value=datetime(int(y),months[m.lower()],int(re.sub(r'\D','',d))).date().isoformat()
        except (ValueError,KeyError):return None
        result[value]={'kind':kind,'spans':[[match.start(),match.end()]]}
        return value
    patterns=[rf'\b(?P<m>{month})\s+(?P<d>{day}),?\s+(?P<y>\d{{4}})\b',
              rf'\b(?P<d>{day})\s+(?P<m>{month}),?\s+(?P<y>\d{{4}})\b']
    for pattern in patterns:
        for match in list(re.finditer(pattern,text,re.I))[:64]:
            add(match['m'],match['d'],match['y'],match,'explicit_calendar_date')
    pattern=rf'\b(?P<m1>{month})\s+(?P<d1>{day})\s+(?:to|through|until)\s+(?:(?P<m2>{month})\s+)?(?P<d2>{day}),?\s+(?P<y>\d{{4}})\b'
    for match in list(re.finditer(pattern,text,re.I))[:64]:
        try:
            start=datetime(int(match['y']),months[match['m1'].lower()],int(re.sub(r'\D','',match['d1']))).date()
            end=datetime(int(match['y']),months[(match['m2'] or match['m1']).lower()],int(re.sub(r'\D','',match['d2']))).date()
        except ValueError:continue
        if end<start:continue
        for value in (start,end):
            result[value.isoformat()]={'kind':'explicit_calendar_range','spans':[[match.start(),match.end()]]}
    return result


def argument_provenance(user_text, arguments, contract, *, state_hash, new_resource_fields=()):
    """Return a complete or incomplete evidence report without granting access."""
    text = str(user_text)
    base = {'version': 1, 'kind': 'user_argument_sources',
            'user_hash': object_hash(text), 'arguments_hash': object_hash(arguments),
            'contract_hash': contract.fingerprint, 'state_hash': state_hash,
            'complete': False, 'fields': {}, 'missing_fields': []}
    if len(text) > MAX_TEXT or set(arguments) != set(contract.fields):
        base['missing_fields'] = sorted(arguments)
        return base
    temporal = {**_calendar_dates(text), **_datetimes(text)}
    nodes = 0

    def witness(value, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES or depth > 8:
            return None
        if isinstance(value, str):
            return _span(text, value) or temporal.get(value)
        if isinstance(value, list) and value:
            children = [witness(v, depth+1) for v in value]
            return {'kind': 'user_list', 'items': children} if all(children) else None
        if type(value) in (int,float):
            try:
                expected=Decimal(str(value))
                if not expected.is_finite():
                    return None
                for match in re.finditer(r'(?<![\w./-])-?\d+(?:\.\d+)?',text):
                    after=text[match.end():match.end()+1]
                    if after=='.' and (match.end()+1==len(text) or text[match.end()+1].isspace()):
                        after=''
                    if after and (after.isalnum() or after in '@_./%-'):
                        continue
                    if Decimal(match.group())==expected:
                        return {'kind':'user_number','span':[match.start(),match.end()],
                                'decimal_value':str(expected)}
            except InvalidOperation:
                return None
        # Unknown objects and implicit/empty defaults have no provenance unless
        # explicitly reviewed by the operator below. No generic default bypass.
        return None

    for field, value in arguments.items():
        declaration = contract.fields[field]
        if declaration.get('mode') == 'no_additional_effect' and any(
                typed_equal(value, v) for v in declaration['values']):
            proof = {'kind': 'operator_no_additional_effect'}
        elif declaration['role'] == 'execution' or (
                declaration['role'] == 'resource' and field not in new_resource_fields):
            # A resource ID can cause implicit disclosure or mutation of its
            # existing contents. A literal occurrence alone cannot bound that.
            proof = None
        else:
            proof = witness(value)
        base['fields'][field] = proof or {'kind': 'unproven'}
        if proof is None:
            base['missing_fields'].append(field)
    base['complete'] = not base['missing_fields']
    return base
