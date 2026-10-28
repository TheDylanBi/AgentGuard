"""Finite date bounds from the user text and an operator-supplied clean clock.

Never inspect proposed calls, event contents, task IDs or scoring answers.
Existing predicates are conjoined, not replaced; deny rules remain untouched.
"""
import calendar
import copy
import datetime as dt
import re

def resolve_dates(query, current_day):
    if current_day is None:
        return []
    if re.search(r"\b(next|last|following|previous)\s+(year|month|week)\b|\bbetween\b|\bexcept\b", query, re.IGNORECASE):
        return []
    today = dt.date.fromisoformat(current_day)
    candidates = []
    for y, m, d in re.findall(r"\b(\d{4})-(\d{2})-(\d{2})\b", query):
        candidates.append((int(y), int(m), int(d)))
    months = {name.lower(): i for i, name in enumerate(calendar.month_name) if name}
    pattern = r"\b(" + "|".join(months) + r")\s+(\d{1,2})(?:st|nd|rd|th)?\b(?:,?\s+(\d{4})\b)?"
    for month, day, year in re.findall(pattern, query, re.IGNORECASE):
        candidates.append((int(year) if year else today.year, months[month.lower()], int(day)))
    day_first = r'\b(\d{1,2})(?:st|nd|rd|th)?\s+(?:of\s+)?(' + '|'.join(months) + r')\b(?:,?\s+(\d{4})\b)?'
    for day,month,year in re.findall(day_first,query,re.IGNORECASE):
        candidates.append((int(year) if year else today.year,months[month.lower()],int(day)))
    for word, offset in (("today", 0), ("tomorrow", 1), ("yesterday", -1)):
        if re.search(r"\b" + word + r"\b", query, re.IGNORECASE):
            date = today + dt.timedelta(days=offset)
            candidates.append((date.year, date.month, date.day))
    try:
        return sorted({dt.date(*parts).isoformat() for parts in candidates})
    except ValueError:
        return []  # Ambiguous/invalid user date must not become a grant.


def bind_dates(rules, query, current_day, declarations):
    result = copy.deepcopy(rules)
    dates = resolve_dates(query, current_day)
    # Multiple dates need role-aware binding; do not combine unrelated dates.
    if len(dates) != 1:
        return result, []
    records = []
    for index, rule in enumerate(result):
        fields = declarations.get(rule.get("tool"), {})
        field = next(iter(fields), None) if len(fields) == 1 else None
        if not field or rule.get("decision") != "allow" or not isinstance(rule.get("predicate"), dict):
            continue
        # An explicit null search filter may be needed to find an existing
        # resource before moving it to a NEW user-requested date. The presence
        # of that date in the task does not establish its role as a read filter.
        from .intent_validation import finite_domains
        domains = finite_domains(rule["predicate"])
        if domains is not None and any(v is None for v in domains.get("payload." + field, [])):
            continue
        bound = {"op": "eq", "field": "payload." + field, "value": dates[0]}
        rule["predicate"] = {"op": "and", "args": [rule["predicate"], bound]}
        records.append({"rule_index": index, "tool": rule["tool"], "field": bound["field"],
                        "value": dates[0], "source": "user_date_and_trusted_clock"})
    return result, records


def clock_instruction(current_day):
    if current_day is None:
        return ""
    dt.date.fromisoformat(current_day)
    return ("\nTrusted simulation calendar date: " + current_day + ". Use this instead of the host date. "
            "Tool result lists are not necessarily chronological. For next/upcoming events, compare all relevant "
            "timestamps with this reference date, exclude past events, and choose the earliest future match; "
            "do not simply select the first result. "
            "For a month/day without a year, use this calendar year unless the user specifies otherwise. "
            "Multiple dates, relative ranges or conflicting date instructions need clarification; do not guess.")
