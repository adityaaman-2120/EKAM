"""Cryptographic hashing of raw events at the moment of ingest.

The hash must be taken over the **original bytes**, before any decoding, newline
stripping, charset guessing, framing removal, or normalization. Those steps can
lose or alter data (a stray ``\\r``, a mis-guessed charset, a trimmed trailing
space), so a hash computed *after* them proves only that our own processed
output is internally consistent — it says nothing about what the sensor actually
sent. Hashing first makes the raw event tamper-evident from the earliest point
ULPF controls, which is the whole point of the bronze/evidence tier and of
requirement (a): preserve complete raw event data without information loss.

``make_raw_event`` is therefore the only sanctioned way to admit bytes into the
pipeline: it stamps the UUIDv7, hashes the untouched bytes, and records the
ingest time, all before any other stage sees the event.
"""

from __future__ import annotations

import hashlib
import time

from ulpf.core.ids import new_event_uid
from ulpf.core.models import RawEvent, Transport


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def make_raw_event(
    raw: bytes,
    source_id: str,
    transport: Transport,
    peer: str | None = None,
) -> RawEvent:
    """Admit raw bytes into the pipeline as a :class:`RawEvent`.

    Generates a UUIDv7, computes the SHA-256 of ``raw`` exactly as received
    (no decoding or stripping), records ``ingest_time_ns`` as the current UTC
    epoch nanoseconds, and stores ``raw`` unmodified.

    Args:
        raw: The original event bytes, untouched.
        source_id: Identifier of the listener/source that produced the event.
        transport: One of ``udp``/``tcp``/``tls``/``http``/``file``.
        peer: Sending IP address, if known.
    """
    return RawEvent(
        event_uid=new_event_uid(),
        raw=raw,
        raw_hash=sha256_hex(raw),
        raw_len=len(raw),
        ingest_time_ns=time.time_ns(),
        source_id=source_id,
        transport=transport,
        peer=peer,
    )
