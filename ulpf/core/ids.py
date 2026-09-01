"""Identifier generation for ULPF events.

We stamp every ingested event with a UUIDv7 rather than a UUIDv4:

* **Time-sortable.** UUIDv7 embeds a millisecond Unix timestamp in its most
  significant bits, so lexical ordering of the string matches creation order.
  Dead-letter triage, replay, and "events since X" scans become range scans.
* **Storage locality.** Because successive ids share a common prefix, rows land
  next to each other in Parquet row groups, DuckDB/ClickHouse primary indexes,
  and B-trees. UUIDv4's randomness scatters writes across the keyspace and
  bloats indexes. UUIDv7 keeps inserts append-mostly.
* Still 122 bits of entropy in the tail, so collision risk stays negligible.
"""

from __future__ import annotations

from uuid6 import uuid7


def new_event_uid() -> str:
    """Return a fresh UUIDv7 as a canonical hyphenated string."""
    return str(uuid7())
