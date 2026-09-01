"""Timestamp handling for ULPF.

All internal timestamps are UTC epoch **nanoseconds** (``int``). This module is
the single place raw timestamp strings/numbers are turned into that form.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, tzinfo
from decimal import ROUND_HALF_EVEN, Decimal

from dateutil.parser import isoparse
from dateutil.parser import parse as _dateutil_parse
from dateutil.tz import gettz

from ulpf.core.errors import ParseError

_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_NUMERIC_RE = re.compile(r"^-?\d+(\.\d+)?$")
_RFC3164_RE = re.compile(r"^[A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2}$")
_RFC3164_FMT = "%b %d %H:%M:%S"

# Numbers at or above this magnitude are epoch milliseconds; below, epoch
# seconds. 1e11 s is year 5138 and 1e11 ms is year 1973, so real-world log
# timestamps never straddle the boundary.
_EPOCH_MS_THRESHOLD = 100_000_000_000


def to_utc_ns(dt: datetime) -> int:
    """Convert a ``datetime`` to UTC epoch nanoseconds.

    A naive ``datetime`` is assumed to already be UTC.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = dt.astimezone(UTC) - _UNIX_EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1_000


def parse_timestamp(
    value: str | int | float,
    fmt: str | None = None,
    tz: str | tzinfo | None = None,
    reference_year: int | None = None,
) -> int:
    """Parse a raw timestamp into UTC epoch nanoseconds.

    Handles ISO 8601 / RFC 3339, RFC 3164 syslog style (``Oct 11 22:14:15``,
    no year), epoch seconds, and epoch milliseconds. ``fmt`` forces an explicit
    ``strptime`` pattern. ``tz`` (an IANA name or ``tzinfo``) is applied only
    when the parsed value is naive; it defaults to UTC. ``reference_year`` pins
    the year for RFC 3164 input.
    """
    zone = _resolve_tz(tz)
    if fmt is not None:
        return _finalize(datetime.strptime(str(value), fmt), zone)

    text = str(value).strip()
    if isinstance(value, (int, float)) or _NUMERIC_RE.match(text):
        return _epoch_to_ns(text)

    normalized = re.sub(r"\s+", " ", text)
    rfc3164 = _try_rfc3164(normalized, reference_year, zone)
    if rfc3164 is not None:
        return to_utc_ns(rfc3164)
    return _finalize(_parse_datetime_string(normalized), zone)


def _resolve_tz(tz: str | tzinfo | None) -> tzinfo:
    """Return a ``tzinfo`` for ``tz`` (name or object), defaulting to UTC."""
    if tz is None:
        return UTC
    if isinstance(tz, tzinfo):
        return tz
    zone = gettz(tz)
    if zone is None:
        raise ParseError("unknown timezone", detail={"tz": tz})
    return zone


def _finalize(dt: datetime, zone: tzinfo) -> int:
    """Attach ``zone`` to a naive ``datetime`` then convert to epoch ns."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=zone)
    return to_utc_ns(dt)


def _epoch_to_ns(text: str) -> int:
    """Scale an epoch value (seconds or milliseconds) to nanoseconds exactly.

    ``Decimal`` keeps large millisecond values precise where ``float`` would
    round them off past 2**53.
    """
    number = Decimal(text)
    scale = 1_000_000 if abs(number) >= _EPOCH_MS_THRESHOLD else 1_000_000_000
    return int((number * scale).to_integral_value(rounding=ROUND_HALF_EVEN))


def _try_rfc3164(text: str, reference_year: int | None, zone: tzinfo) -> datetime | None:
    """Parse yearless RFC 3164 time, resolving the year; ``None`` if no match."""
    if not _RFC3164_RE.match(text):
        return None
    year = reference_year if reference_year is not None else datetime.now(UTC).year
    candidate = _rfc3164_with_year(text, year, zone)
    if candidate is None:  # e.g. "Feb 29" and `year` is not a leap year.
        return _rfc3164_with_year(text, year - 1, zone)
    # Year-boundary bug fix: a line like "Dec 31 23:59:59" processed on Jan 1
    # would be stamped ~1 year in the future if we blindly assume the current
    # year. If the guess lands ahead of now, the event is from the prior year.
    if candidate.astimezone(UTC) > datetime.now(UTC):
        prior = _rfc3164_with_year(text, year - 1, zone)
        return prior if prior is not None else candidate
    return candidate


def _rfc3164_with_year(text: str, year: int, zone: tzinfo) -> datetime | None:
    """Bind ``text`` to ``year``; ``None`` if the day is invalid for that year."""
    try:
        parsed = datetime.strptime(f"{year} {text}", f"%Y {_RFC3164_FMT}")
    except ValueError:
        return None
    return parsed.replace(tzinfo=zone)


def _parse_datetime_string(text: str) -> datetime:
    """Parse an ISO 8601 / RFC 3339 (or otherwise dateutil-parseable) string."""
    try:
        return isoparse(text)
    except ValueError:
        pass
    try:
        return _dateutil_parse(text)
    except (ValueError, OverflowError) as exc:
        raise ParseError("unrecognized timestamp", detail={"value": text}) from exc
