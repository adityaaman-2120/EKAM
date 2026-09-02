"""Prometheus metrics for ULPF.

All metrics are module-level singletons registered on the default registry, so
any stage can ``from ulpf.core import metrics`` and record without wiring.
``snapshot`` gives the API a plain dict for a JSON endpoint; the standard
Prometheus exposition format is still available via ``prometheus_client``.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from prometheus_client import Counter, Gauge, Histogram

EVENTS_RECEIVED = Counter(
    "ulpf_events_received_total",
    "Raw events accepted by a listener.",
    ["transport"],
)
BYTES_RECEIVED = Counter(
    "ulpf_bytes_received_total",
    "Raw bytes accepted by a listener.",
    ["transport"],
)
EVENTS_PARSED = Counter(
    "ulpf_events_parsed_total",
    "Events whose source-specific attributes were extracted.",
    ["source_type"],
)
EVENTS_NORMALIZED = Counter(
    "ulpf_events_normalized_total",
    "Events mapped into the OCSF taxonomy.",
    ["source_type", "class_uid"],
)
DEAD_LETTER = Counter(
    "ulpf_dead_letter_total",
    "Events routed to the dead-letter queue.",
    ["stage", "reason"],
)
QUEUE_BACKPRESSURE_WAITS = Counter(
    "ulpf_queue_backpressure_waits_total",
    "Times a producer had to wait for intake-queue space (backpressure applied).",
)

QUEUE_DEPTH = Gauge(
    "ulpf_queue_depth",
    "Current number of events waiting in the intake queue.",
)
ACTIVE_SOURCES = Gauge(
    "ulpf_active_sources",
    "Number of configured log sources currently loaded.",
)
PARSE_SUCCESS_RATE = Gauge(
    "ulpf_parse_success_rate",
    "Rolling ratio of parsed to received events, in [0, 1].",
)

STAGE_LATENCY = Histogram(
    "ulpf_stage_latency_seconds",
    "Wall-clock time spent in a single pipeline stage.",
    ["stage"],
)
END_TO_END_LATENCY = Histogram(
    "ulpf_end_to_end_latency_seconds",
    "Wall-clock time from ingest to sink for one event.",
)
NORMALIZATION_COMPLETENESS = Histogram(
    "ulpf_normalization_completeness",
    "Fraction of an OCSF class's required+recommended attributes populated, per event.",
    buckets=(0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

_ALL_METRICS = (
    EVENTS_RECEIVED,
    BYTES_RECEIVED,
    EVENTS_PARSED,
    EVENTS_NORMALIZED,
    DEAD_LETTER,
    QUEUE_BACKPRESSURE_WAITS,
    QUEUE_DEPTH,
    ACTIVE_SOURCES,
    PARSE_SUCCESS_RATE,
    STAGE_LATENCY,
    END_TO_END_LATENCY,
    NORMALIZATION_COMPLETENESS,
)


@contextmanager
def timed(stage: str) -> Iterator[None]:
    """Observe the duration of the wrapped block into ``ulpf_stage_latency_seconds``.

    Args:
        stage: Value for the ``stage`` label (e.g. ``"parse"``, ``"normalize"``).
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        STAGE_LATENCY.labels(stage=stage).observe(time.perf_counter() - start)


def snapshot() -> dict[str, float]:
    """Return a flat ``{sample_key: value}`` dict of every ULPF metric's value.

    Keys are the Prometheus sample name with sorted labels, e.g.
    ``ulpf_events_received_total{transport="udp"}``. Internal ``*_created``
    timestamps are omitted.
    """
    out: dict[str, float] = {}
    for metric in _ALL_METRICS:
        for family in metric.collect():
            for sample in family.samples:
                if sample.name.endswith("_created"):
                    continue
                out[_sample_key(sample.name, dict(sample.labels))] = float(sample.value)
    return out


def _sample_key(name: str, labels: dict[str, str]) -> str:
    """Render ``name`` plus label pairs (sorted) as a stable string key."""
    if not labels:
        return name
    inner = ",".join(f'{key}="{labels[key]}"' for key in sorted(labels))
    return f"{name}{{{inner}}}"
