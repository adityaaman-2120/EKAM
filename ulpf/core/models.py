"""Core data contracts shared by every ULPF pipeline stage.

The pipeline is a chain of widening records:

``RawEvent`` -> ``ParsedEvent`` -> ``NormalizedEvent``

with ``DeadLetter`` as the escape hatch when a stage cannot proceed. Two fields
travel end to end so a normalized row can always be tied back to the exact bytes
that produced it (requirement *d*): ``event_uid`` and ``raw_hash``.

``raw`` is evidence: it is set once at ingest and never modified thereafter.
JSON serialization uses base64 for ``bytes`` so arbitrary (non-UTF-8) payloads
round-trip losslessly.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ulpf.core.ids import new_event_uid

Transport = Literal["udp", "tcp", "tls", "http", "file"]
LogFormat = Literal["syslog", "cef", "leef", "json", "kv", "csv", "tsv", "unknown"]

_BYTES_JSON = ConfigDict(ser_json_bytes="base64", val_json_bytes="base64")


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


class RawEvent(BaseModel):
    """An event exactly as received by a listener.

    ``raw`` holds the original bytes untouched; ``raw_hash``/``raw_len`` are
    derived from them at ingest and must stay consistent with ``raw``.
    """

    model_config = _BYTES_JSON

    event_uid: str
    raw: bytes
    raw_hash: str
    raw_len: int
    ingest_time_ns: int
    source_id: str
    transport: Transport
    peer: str | None = None

    @classmethod
    def from_raw(
        cls,
        raw: bytes,
        *,
        source_id: str,
        transport: Transport,
        ingest_time_ns: int,
        peer: str | None = None,
        event_uid: str | None = None,
    ) -> RawEvent:
        """Construct a ``RawEvent``, deriving ``raw_hash`` and ``raw_len``.

        A fresh UUIDv7 is minted for ``event_uid`` unless one is supplied.
        """
        return cls(
            event_uid=event_uid or new_event_uid(),
            raw=raw,
            raw_hash=sha256_hex(raw),
            raw_len=len(raw),
            ingest_time_ns=ingest_time_ns,
            source_id=source_id,
            transport=transport,
            peer=peer,
        )


class ParsedEvent(RawEvent):
    """A ``RawEvent`` after format detection and source-specific extraction."""

    format: LogFormat = "unknown"
    source_type: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    envelope: dict[str, Any] = Field(default_factory=dict)
    template_id: str | None = None


class NormalizedEvent(BaseModel):
    """A ``ParsedEvent`` mapped into the OCSF taxonomy, plus enrichment.

    ``event_uid``, ``raw_hash`` and ``ingest_time_ns`` are carried through from
    the raw event to preserve traceability.
    """

    event_uid: str
    raw_hash: str
    ingest_time_ns: int
    ocsf: dict[str, Any]
    source_type: str
    mapping_version: str
    enrichment: dict[str, Any] = Field(default_factory=dict)

    def traceability(self) -> dict[str, str]:
        """Return the immutable link back to the original event (requirement d)."""
        return {"event_uid": self.event_uid, "raw_hash": self.raw_hash}


class DeadLetter(BaseModel):
    """A record that a stage could not process. Never silently dropped."""

    model_config = _BYTES_JSON

    event_uid: str
    raw: bytes
    raw_hash: str
    reason: str
    stage: str
    detail: dict[str, Any] = Field(default_factory=dict)
    ts_ns: int
