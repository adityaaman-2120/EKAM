"""Shared retry/backoff delivery helper for the *best-effort* export sinks.

:mod:`ulpf.sinks.opensearch_sink` and :mod:`ulpf.sinks.splunk_hec_sink` are
optional, best-effort exports: unlike
:class:`~ulpf.sinks.clickhouse_sink.ClickHouseSink` (which blocks upstream
writers rather than ever dropping an event) they retry a failed batch with
exponential backoff and then, if it still will not go, **log and drop it** so
one flaky external service can never back up or stall the pipeline. This
module is the one retry loop both of them share.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable


class RetryableDeliveryError(RuntimeError):
    """A delivery attempt failed in a way worth retrying (transport error, 5xx, 429)."""


class FatalDeliveryError(RuntimeError):
    """A delivery attempt failed in a way retrying cannot fix (4xx — bad auth/payload)."""


async def deliver_with_retry(
    send: Callable[[], Awaitable[None]],
    *,
    max_retries: int,
    backoff_base_seconds: float,
    backoff_max_seconds: float,
    sleep: Callable[[float], Awaitable[None]],
    on_attempt_failed: Callable[[int, Exception, bool], None] | None = None,
) -> bool:
    """Call ``send()``, retrying on :class:`RetryableDeliveryError` with backoff.

    Args:
        send: Performs one delivery attempt; raises :class:`RetryableDeliveryError`
            / :class:`FatalDeliveryError` on failure, returns normally on success.
        max_retries: Extra attempts after the first (0 = try once, no retry).
        backoff_base_seconds / backoff_max_seconds: Delay doubles each retry,
            capped at ``backoff_max_seconds``.
        sleep: Awaitable delay function (injectable for tests).
        on_attempt_failed: Optional ``(attempt, exc, is_fatal)`` callback for logging/metrics.

    Returns:
        ``True`` if ``send()`` eventually succeeded, ``False`` if a
        :class:`FatalDeliveryError` occurred or retries were exhausted — the
        caller should log the drop and move on, never block on this result.
    """
    for attempt in range(max_retries + 1):
        try:
            await send()
        except FatalDeliveryError as exc:
            if on_attempt_failed is not None:
                on_attempt_failed(attempt, exc, True)
            return False
        except RetryableDeliveryError as exc:
            if on_attempt_failed is not None:
                on_attempt_failed(attempt, exc, False)
            if attempt >= max_retries:
                return False
            await sleep(min(backoff_base_seconds * (2**attempt), backoff_max_seconds))
        else:
            return True
    return False
