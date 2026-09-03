"""The per-event integrity index — ``event_uid -> (ledger_seq, leaf_index)``.

When :class:`~ulpf.integrity.stage.IntegrityStage` seals a batch it records the
Merkle root in the signed ledger and writes one row per event here. That row is
all an auditor needs, months later, to rebuild the O(log n) inclusion proof for
a single event: look up its ``(ledger_seq, leaf_index)``, re-hash the events of
that batch from the bronze store, and call
:func:`ulpf.integrity.merkle.merkle_proof` for ``leaf_index`` — then check it
against the ledger entry's ``batch_root``.

Backed by a single-file SQLite database (``event_index.sqlite`` next to the
ledger). A point lookup is the only hot query, so a primary-key table is enough;
no external service, no schema migrations.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS event_index (
    event_uid  TEXT    PRIMARY KEY,
    ledger_seq INTEGER NOT NULL,
    leaf_index INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS event_index_by_seq ON event_index (ledger_seq);
"""


class IntegrityIndex:
    """Append-only map from ``event_uid`` to its position in a sealed batch."""

    def __init__(self, path: str | Path) -> None:
        """Open (creating the file and schema if needed) the SQLite index at ``path``."""
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def add_batch(self, ledger_seq: int, event_uids: Sequence[str]) -> None:
        """Record every event of a just-sealed batch (row i -> ``leaf_index = i``)."""
        rows = [(uid, ledger_seq, i) for i, uid in enumerate(event_uids)]
        self._conn.executemany(
            "INSERT OR REPLACE INTO event_index (event_uid, ledger_seq, leaf_index) "
            "VALUES (?, ?, ?)",
            rows,
        )
        self._conn.commit()

    def lookup(self, event_uid: str) -> tuple[int, int] | None:
        """Return ``(ledger_seq, leaf_index)`` for ``event_uid``, or ``None``."""
        row = self._conn.execute(
            "SELECT ledger_seq, leaf_index FROM event_index WHERE event_uid = ?",
            (event_uid,),
        ).fetchone()
        return (int(row[0]), int(row[1])) if row is not None else None

    def event_uids_for_batch(self, ledger_seq: int) -> list[str]:
        """Every ``event_uid`` in batch ``ledger_seq``, ordered by ``leaf_index``."""
        rows = self._conn.execute(
            "SELECT event_uid FROM event_index WHERE ledger_seq = ? ORDER BY leaf_index",
            (ledger_seq,),
        ).fetchall()
        return [str(row[0]) for row in rows]

    def __len__(self) -> int:
        """Total number of indexed events."""
        return int(self._conn.execute("SELECT COUNT(*) FROM event_index").fetchone()[0])

    def close(self) -> None:
        """Close the underlying database connection."""
        self._conn.close()
