"""Tests for :mod:`ulpf.core.timeutil`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from dateutil.tz import gettz

from ulpf.core.errors import ParseError
from ulpf.core.timeutil import parse_timestamp, to_utc_ns

_SEC = 1_000_000_000


def _oracle_ns(dt: datetime) -> int:
    """Independent epoch-ns reference not using the module under test."""
    return int(round(dt.timestamp() * _SEC))


def test_to_utc_ns_aware_and_naive() -> None:
    aware = datetime(2023, 10, 11, 22, 14, 15, tzinfo=timezone.utc)
    naive = datetime(2023, 10, 11, 22, 14, 15)
    assert to_utc_ns(aware) == _oracle_ns(aware)
    assert to_utc_ns(naive) == to_utc_ns(aware)


def test_iso8601_utc_z() -> None:
    expected = _oracle_ns(datetime(2023, 10, 11, 22, 14, 15, tzinfo=timezone.utc))
    assert parse_timestamp("2023-10-11T22:14:15Z") == expected


def test_iso8601_with_offset() -> None:
    expected = _oracle_ns(datetime(2023, 10, 11, 16, 44, 15, tzinfo=timezone.utc))
    assert parse_timestamp("2023-10-11T22:14:15+05:30") == expected


def test_iso8601_fractional_seconds() -> None:
    base = datetime(2023, 10, 11, 22, 14, 15, 500_000, tzinfo=timezone.utc)
    assert parse_timestamp("2023-10-11T22:14:15.5Z") == _oracle_ns(base)


def test_epoch_seconds_int_and_str() -> None:
    assert parse_timestamp(1697062455) == 1697062455 * _SEC
    assert parse_timestamp("1697062455") == 1697062455 * _SEC


def test_epoch_seconds_fractional() -> None:
    assert parse_timestamp("1697062455.250") == 1697062455 * _SEC + 250_000_000


def test_epoch_millis() -> None:
    assert parse_timestamp(1697062455123) == 1697062455123 * 1_000_000
    assert parse_timestamp("1697062455123") == 1697062455123 * 1_000_000


def test_explicit_fmt_is_treated_as_utc() -> None:
    expected = _oracle_ns(datetime(2023, 10, 11, 22, 14, 15, tzinfo=timezone.utc))
    assert parse_timestamp("11/10/2023 22:14:15", fmt="%d/%m/%Y %H:%M:%S") == expected


def test_tz_applied_to_naive_value() -> None:
    ny = gettz("America/New_York")
    expected = _oracle_ns(datetime(2023, 10, 11, 22, 14, 15, tzinfo=ny))
    assert parse_timestamp("2023-10-11 22:14:15", tz="America/New_York") == expected


def test_unknown_tz_raises() -> None:
    with pytest.raises(ParseError):
        parse_timestamp("2023-10-11 22:14:15", tz="Mars/Olympus")


def test_rfc3164_recent_date_gets_matching_year() -> None:
    """A yearless syslog time a month ago resolves to that calendar date."""
    past = datetime.now(timezone.utc) - timedelta(days=30)
    ns = parse_timestamp(past.strftime("%b %d %H:%M:%S"))
    got = datetime.fromtimestamp(ns / _SEC, timezone.utc)
    assert (got.year, got.month, got.day) == (past.year, past.month, past.day)


def test_rfc3164_single_digit_day_padding() -> None:
    """Double-space day padding ('Oct  9') is accepted."""
    ns = parse_timestamp("Oct  9 08:05:01", reference_year=2023)
    got = datetime.fromtimestamp(ns / _SEC, timezone.utc)
    assert (got.year, got.month, got.day, got.hour) == (2023, 10, 9, 8)


def test_rfc3164_year_boundary_rolls_back() -> None:
    """A future-dated yearless line is pushed to the previous year (bug fix)."""
    future = datetime.now(timezone.utc) + timedelta(days=3)
    ns = parse_timestamp(future.strftime("%b %d %H:%M:%S"))
    got = datetime.fromtimestamp(ns / _SEC, timezone.utc)
    assert got.year == future.year - 1
    assert (got.month, got.day) == (future.month, future.day)


def test_rfc3164_reference_year_forces_future_then_rolls_back() -> None:
    """reference_year pinned to now, with a clearly future date, still rolls back."""
    now = datetime.now(timezone.utc)
    future = now + timedelta(days=40)
    ns = parse_timestamp(future.strftime("%b %d %H:%M:%S"), reference_year=now.year)
    got = datetime.fromtimestamp(ns / _SEC, timezone.utc)
    assert got <= now


def test_unrecognized_timestamp_raises() -> None:
    with pytest.raises(ParseError):
        parse_timestamp("not-a-timestamp")
