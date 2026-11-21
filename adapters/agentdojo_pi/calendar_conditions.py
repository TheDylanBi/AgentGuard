"""Recognize and verify explicit calendar availability conditions."""
import re
from datetime import datetime, timedelta

from attestation.hashing import object_hash
from policy.task_derivations import duration_candidates


_DAY = r"(?P<day>\d{4}-\d{2}-\d{2})"
_CLOCK = r"(?:[01]?\d|2[0-3]):[0-5]\d"
_ALTERNATE = re.compile(
    rf"\bon {_DAY} at (?P<first>{_CLOCK}) or (?:at )?(?P<second>{_CLOCK}) "
    rf"if at (?P=first) I already have something\b", re.IGNORECASE
)
_IF_FREE = re.compile(
    rf"\b(?:am I|check if I am) free\b[^\n.!?]*?\bat (?P<first>{_CLOCK}) "
    rf"on {_DAY}[?.,]\s*if so\b", re.IGNORECASE
)
_TIME_FIELDS = {
    "create_calendar_event": ("start_time", "end_time"),
    "reschedule_calendar_event": ("new_start_time", "new_end_time"),
}


def normalize_calendar_times(tool, arguments):
    from policy.argument_provenance import minute_precision_timestamp

    normalized = dict(arguments)
    for field in _TIME_FIELDS.get(tool, ()):
        if field in normalized:
            normalized[field] = minute_precision_timestamp(normalized[field])
    return normalized


def calendar_availability(query, arguments, calendar, day_reads):
    """Return missing/conflict/matched for a supported conditional create.

    Require a successful same-day observation of the current calendar. Use native
    timestamps and statuses only. Neither event prose nor a search subset can
    establish availability. General language conditions still require review.
    """
    match = _ALTERNATE.search(query) or _IF_FREE.search(query)
    durations = {value["minutes"] for value in duration_candidates(query)}
    if match is None or len(durations) != 1:
        return None
    day = match["day"]
    try:
        first = datetime.strptime(day + " " + match["first"], "%Y-%m-%d %H:%M")
        second_text = match.groupdict().get("second")
        second = datetime.strptime(day + " " + second_text, "%Y-%m-%d %H:%M") if second_text else None
        duration = timedelta(minutes=next(iter(durations)))
        interval_end = first + duration
    except (ValueError, OverflowError):
        return None

    evidence = {"day": day, "first_start": first.isoformat(timespec="minutes"), "status": "missing"}
    receipt = day_reads.get(day)
    if not receipt or receipt["calendar_hash"] != object_hash(calendar):
        return evidence
    try:
        occupied = any(
            datetime.fromisoformat(event["start_time"]) < interval_end
            and first < datetime.fromisoformat(event["end_time"])
            for event in calendar["events"].values() if event["status"] != "canceled"
        )
        expected = second if occupied else first
        expected_start = expected.strftime("%Y-%m-%d %H:%M") if expected else None
        expected_end = (expected + duration).strftime("%Y-%m-%d %H:%M") if expected else None
    except (KeyError, ValueError, TypeError, OverflowError):
        return evidence
    matches = (expected is not None and arguments["start_time"] == expected_start
               and arguments["end_time"] == expected_end)
    return {**evidence, "status": "matched" if matches else "conflict",
            "initial_slot_occupied": occupied, "required_start": expected_start,
            "required_end": expected_end, "observation_id": "obs:" + receipt["call_id"]}
