"""Tests for the shared :mod:`ulpf.sinks._delivery` retry/backoff helper."""

from __future__ import annotations

import pytest

from ulpf.sinks._delivery import FatalDeliveryError, RetryableDeliveryError, deliver_with_retry


class RecordingSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.calls.append(delay)


async def test_success_on_first_try_needs_no_sleep() -> None:
    calls = []

    async def send() -> None:
        calls.append(1)

    sleep = RecordingSleep()
    ok = await deliver_with_retry(
        send, max_retries=3, backoff_base_seconds=1.0, backoff_max_seconds=10.0, sleep=sleep
    )
    assert ok is True and len(calls) == 1 and sleep.calls == []


async def test_retries_then_succeeds_with_exponential_backoff() -> None:
    attempts = {"n": 0}

    async def send() -> None:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RetryableDeliveryError("not yet")

    sleep = RecordingSleep()
    ok = await deliver_with_retry(
        send, max_retries=5, backoff_base_seconds=0.5, backoff_max_seconds=30.0, sleep=sleep
    )
    assert ok is True and attempts["n"] == 3
    assert sleep.calls == [0.5, 1.0]


async def test_backoff_is_capped_at_backoff_max() -> None:
    async def send() -> None:
        raise RetryableDeliveryError("always")

    sleep = RecordingSleep()
    ok = await deliver_with_retry(
        send, max_retries=4, backoff_base_seconds=1.0, backoff_max_seconds=2.5, sleep=sleep
    )
    assert ok is False
    assert sleep.calls == [1.0, 2.0, 2.5, 2.5]


async def test_retries_exhausted_returns_false() -> None:
    attempts = {"n": 0}

    async def send() -> None:
        attempts["n"] += 1
        raise RetryableDeliveryError("down")

    ok = await deliver_with_retry(
        send, max_retries=2, backoff_base_seconds=0.01, backoff_max_seconds=1.0, sleep=RecordingSleep()
    )
    assert ok is False and attempts["n"] == 3  # first try + 2 retries


async def test_fatal_error_stops_immediately_without_retry() -> None:
    attempts = {"n": 0}

    async def send() -> None:
        attempts["n"] += 1
        raise FatalDeliveryError("bad request")

    sleep = RecordingSleep()
    ok = await deliver_with_retry(
        send, max_retries=5, backoff_base_seconds=1.0, backoff_max_seconds=10.0, sleep=sleep
    )
    assert ok is False and attempts["n"] == 1 and sleep.calls == []


async def test_on_attempt_failed_callback_receives_attempt_and_fatality() -> None:
    seen: list[tuple[int, bool]] = []

    async def send() -> None:
        if len(seen) == 0:
            raise RetryableDeliveryError("retry me")
        raise FatalDeliveryError("now fatal")

    def on_fail(attempt: int, exc: Exception, fatal: bool) -> None:
        seen.append((attempt, fatal))

    ok = await deliver_with_retry(
        send, max_retries=5, backoff_base_seconds=0.01, backoff_max_seconds=1.0,
        sleep=RecordingSleep(), on_attempt_failed=on_fail,
    )
    assert ok is False
    assert seen == [(0, False), (1, True)]


@pytest.mark.parametrize("max_retries", [0])
async def test_max_retries_zero_tries_exactly_once(max_retries: int) -> None:
    attempts = {"n": 0}

    async def send() -> None:
        attempts["n"] += 1
        raise RetryableDeliveryError("down")

    ok = await deliver_with_retry(
        send, max_retries=max_retries, backoff_base_seconds=0.01, backoff_max_seconds=1.0,
        sleep=RecordingSleep(),
    )
    assert ok is False and attempts["n"] == 1
