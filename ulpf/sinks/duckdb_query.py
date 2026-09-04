"""Zero-infrastructure querying over the Parquet lake, with DuckDB.

ULPF's analytical database is ClickHouse. But a demo box, an air-gapped tin, or
a fresh checkout has no ClickHouse — and the whole point of the silver tier is
that the data is *just Parquet files on disk*. :class:`LakeQuery` opens an
**in-memory** DuckDB (no server, no daemon, no config, one pip dependency that
is already required) and exposes two SQL views straight over the files:

* ``events``       — ``read_parquet(silver_path/**/*.parquet)`` with
  ``union_by_name`` (so schema drift between part files just works) and Hive
  partitioning (so ``date`` / ``source_type`` come from the directory names);
* ``dead_letters`` — ``read_json_auto`` over the DLQ NDJSON partitions.

The API layer uses this whenever ClickHouse is not configured, so ``ulpf`` and
its dashboard run with **zero external services**. Queries are **read-only**:
:meth:`LakeQuery.query` rejects any statement that is not a single ``SELECT`` /
``WITH``, and refuses DDL/DML keywords anywhere in the text (a ``WITH`` may
legally precede an ``INSERT`` in DuckDB, so the start keyword alone is not
enough).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import duckdb

from ulpf.config.settings import Settings
from ulpf.core.errors import UlpfError

_log = logging.getLogger(__name__)

_MAX_LIMIT = 10_000

# Columns the silver Parquet writer always emits (see ulpf.sinks.parquet_sink),
# plus the Hive partition column ``date``. Used for the empty-lake fallback view
# and as the allow-list for :meth:`LakeQuery.search`.
_EVENT_COLUMNS: dict[str, str] = {
    "event_uid": "VARCHAR",
    "raw_hash": "VARCHAR",
    "time": "BIGINT",
    "class_uid": "BIGINT",
    "category_uid": "BIGINT",
    "activity_id": "BIGINT",
    "type_uid": "BIGINT",
    "severity_id": "BIGINT",
    "source_type": "VARCHAR",
    "src_ip": "VARCHAR",
    "src_port": "BIGINT",
    "dst_ip": "VARCHAR",
    "dst_port": "BIGINT",
    "protocol": "VARCHAR",
    "action_id": "BIGINT",
    "bytes_in": "BIGINT",
    "bytes_out": "BIGINT",
    "unmapped_json": "VARCHAR",
    "enrichments_json": "VARCHAR",
    "date": "VARCHAR",
}
_DLQ_COLUMNS: dict[str, str] = {
    "event_uid": "VARCHAR",
    "raw_hash": "VARCHAR",
    "reason": "VARCHAR",
    "stage": "VARCHAR",
    "ts_ns": "BIGINT",
    "detail": "JSON",
}

# unit -> DuckDB interval constructor, for :meth:`timeseries`.
_INTERVAL_FN: dict[str, str] = {
    "second": "to_seconds",
    "minute": "to_minutes",
    "hour": "to_hours",
    "day": "to_days",
    "week": "to_weeks",
}
_INTERVAL_RE = re.compile(r"^\s*(\d+)\s*(second|minute|hour|day|week)s?\s*$", re.IGNORECASE)

_ALLOWED_START = ("SELECT", "WITH")
_FORBIDDEN_KEYWORDS = frozenset(
    {
        "INSERT", "UPDATE", "DELETE", "MERGE", "UPSERT", "DROP", "CREATE", "ALTER",
        "TRUNCATE", "REPLACE", "ATTACH", "DETACH", "COPY", "EXPORT", "IMPORT",
        "INSTALL", "LOAD", "PRAGMA", "SET", "RESET", "CALL", "GRANT", "REVOKE",
        "VACUUM", "CHECKPOINT", "USE",
    }
)


class ReadOnlyViolation(UlpfError):
    """A query passed to :meth:`LakeQuery.query` was not a read-only SELECT/WITH."""


class LakeQuery:
    """In-memory DuckDB with read-only views over the Parquet/NDJSON lake."""

    def __init__(self, settings: Settings) -> None:
        """Record the lake locations; call :meth:`connect` before querying."""
        self._silver = Path(settings.storage.silver_path)
        self._dlq = Path(settings.storage.dlq_path)
        self._conn: duckdb.DuckDBPyConnection | None = None

    # -- lifecycle ----------------------------------------------------

    def connect(self) -> LakeQuery:
        """Open the in-memory database and (re)create the ``events`` / ``dead_letters`` views."""
        self._conn = duckdb.connect(":memory:")
        self._create_view("events", self._parquet_source(), _EVENT_COLUMNS)
        self._create_view("dead_letters", self._ndjson_source(), _DLQ_COLUMNS)
        return self

    def close(self) -> None:
        """Close the database (idempotent)."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> LakeQuery:
        """Connect on ``with`` entry."""
        return self.connect()

    def __exit__(self, *_exc: object) -> None:
        """Close on ``with`` exit."""
        self.close()

    # -- generic query ---------------------------------------------

    def query(
        self, sql: str, params: Sequence[Any] | Mapping[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Run a **read-only** ``SELECT`` / ``WITH`` query and return rows as dicts.

        Raises:
            ReadOnlyViolation: if ``sql`` is not a single SELECT/WITH statement,
                or contains a DDL/DML keyword.
        """
        conn = self._require_conn()
        _assert_read_only(sql)
        bind: list[Any] | dict[str, Any] = (
            dict(params) if isinstance(params, Mapping) else list(params or [])
        )
        cursor = conn.execute(sql, bind)
        columns = [description[0] for description in cursor.description or []]
        return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]

    # -- convenience queries --------------------------------------

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """The most recent events, newest first."""
        return self.query(
            'SELECT * FROM events ORDER BY "time" DESC NULLS LAST LIMIT ?', [_clamp(limit)]
        )

    def by_source(self, source_type: str, limit: int = 100) -> list[dict[str, Any]]:
        """The most recent events for one ``source_type``."""
        return self.query(
            'SELECT * FROM events WHERE source_type = ? ORDER BY "time" DESC NULLS LAST LIMIT ?',
            [source_type, _clamp(limit)],
        )

    def search(self, filters: Mapping[str, Any], limit: int = 100) -> list[dict[str, Any]]:
        """Events matching an equality/range filter map.

        Keys are event column names (``src_ip``, ``dst_port``, ``class_uid``, …)
        for equality, or ``since_ns`` / ``until_ns`` for a ``time`` range. An
        unknown key raises :class:`ValueError`.
        """
        clauses: list[str] = []
        params: list[Any] = []
        for key, value in filters.items():
            if key == "since_ns":
                clauses.append('"time" >= ?')
                params.append(int(value))
            elif key == "until_ns":
                clauses.append('"time" <= ?')
                params.append(int(value))
            elif key in _EVENT_COLUMNS:
                clauses.append(f'"{key}" = ?')
                params.append(value)
            else:
                raise ValueError(f"unknown filter column: {key!r}")
        where = " AND ".join(clauses) if clauses else "TRUE"
        params.append(_clamp(limit))
        return self.query(
            f'SELECT * FROM events WHERE {where} ORDER BY "time" DESC NULLS LAST LIMIT ?', params
        )

    def stats_by_source(self) -> list[dict[str, Any]]:
        """Per-source counts, time span, byte volume and distinct source IPs."""
        return self.query(
            'SELECT source_type,'
            " COUNT(*) AS events,"
            ' MIN("time") AS first_time_ns,'
            ' MAX("time") AS last_time_ns,'
            " COALESCE(SUM(COALESCE(bytes_in, 0) + COALESCE(bytes_out, 0)), 0) AS total_bytes,"
            " COUNT(DISTINCT src_ip) AS distinct_src_ip"
            " FROM events GROUP BY source_type ORDER BY events DESC, source_type"
        )

    def timeseries(self, interval: str, window: str) -> list[dict[str, Any]]:
        """Event counts per ``interval`` bucket, over the last ``window`` of data.

        ``interval`` / ``window`` are ``"<n> <unit>"`` strings where unit is one
        of second/minute/hour/day/week (e.g. ``"5 minutes"``, ``"24 hours"``).
        The window is measured back from the newest bucket, not wall-clock now,
        so it works on historical data too.
        """
        bucket_fn, bucket_n = _interval_parts(interval)
        window_fn, window_n = _interval_parts(window)
        sql = (
            "WITH s AS ("
            f'  SELECT time_bucket({bucket_fn}(?),'
            '         make_timestamp(CAST("time" / 1000 AS BIGINT))) AS bucket, source_type'
            '  FROM events WHERE "time" IS NOT NULL'
            "), mx AS (SELECT max(bucket) AS newest FROM s) "
            "SELECT strftime(s.bucket, '%Y-%m-%dT%H:%M:%S') AS bucket, s.source_type,"
            "       COUNT(*) AS events "
            "FROM s, mx "
            f"WHERE mx.newest IS NOT NULL AND s.bucket >= mx.newest - {window_fn}(?) "
            "GROUP BY s.bucket, s.source_type ORDER BY s.bucket, s.source_type"
        )
        return self.query(sql, [bucket_n, window_n])

    # -- internals -------------------------------------------------

    def _require_conn(self) -> duckdb.DuckDBPyConnection:
        if self._conn is None:
            raise RuntimeError("LakeQuery.connect() has not been called")
        return self._conn

    def _create_view(self, name: str, source: str | None, empty_columns: dict[str, str]) -> None:
        """Create ``name`` over ``source``; fall back to a typed empty view if it cannot be read."""
        conn = self._require_conn()
        if source is not None:
            try:
                conn.execute(f"CREATE OR REPLACE VIEW {name} AS SELECT * FROM {source}")
                return
            except duckdb.Error as exc:  # unreadable / no files -> empty view
                _log.warning("lake view %s: %s; exposing an empty view", name, exc)
        empty = ", ".join(f"CAST(NULL AS {typ}) AS {col}" for col, typ in empty_columns.items())
        conn.execute(f"CREATE OR REPLACE VIEW {name} AS SELECT {empty} WHERE 1 = 0")

    def _parquet_source(self) -> str | None:
        if not any(self._silver.rglob("*.parquet")):
            return None
        glob = (self._silver / "**" / "*.parquet").as_posix()
        # keep ``date`` a plain string (JSON-friendly and identical to the
        # empty-lake fallback view) instead of DuckDB's auto DATE cast.
        return (
            f"read_parquet({_sql_str(glob)}, union_by_name = true, "
            "hive_partitioning = true, hive_types = {'date': 'VARCHAR'})"
        )

    def _ndjson_source(self) -> str | None:
        if not any(self._dlq.rglob("*.ndjson")):
            return None
        glob = (self._dlq / "**" / "*.ndjson").as_posix()
        return (
            "(SELECT event_uid, raw_hash, reason, stage, ts_ns, detail::JSON AS detail "
            f"FROM read_json_auto({_sql_str(glob)}, format = 'newline_delimited', "
            "union_by_name = true))"
        )


# -- helpers -----------------------------------------------------------


def _clamp(limit: int) -> int:
    """Bound a caller-supplied ``LIMIT`` to a sane range."""
    return max(1, min(int(limit), _MAX_LIMIT))


def _sql_str(value: str) -> str:
    """Render ``value`` as a single-quoted SQL string literal."""
    return "'" + value.replace("'", "''") + "'"


def _interval_parts(spec: str) -> tuple[str, int]:
    """Parse ``"5 minutes"`` -> ``("to_minutes", 5)``; raise on anything else."""
    match = _INTERVAL_RE.match(spec)
    if match is None:
        raise ValueError(f"invalid interval {spec!r}; expected '<n> <second|minute|hour|day|week>'")
    return _INTERVAL_FN[match.group(2).lower()], int(match.group(1))


def _assert_read_only(sql: str) -> None:
    """Reject anything that is not a single read-only SELECT/WITH statement."""
    cleaned = _mask_literals(_strip_comments(sql)).strip().rstrip(";").strip()
    if not cleaned:
        raise ReadOnlyViolation("empty query")
    if ";" in cleaned:
        raise ReadOnlyViolation("multiple statements are not allowed")
    head = re.match(r"[A-Za-z_]+", cleaned)
    if head is None or head.group(0).upper() not in _ALLOWED_START:
        got = head.group(0) if head else cleaned[:16]
        raise ReadOnlyViolation(f"only read-only SELECT/WITH queries are allowed (got {got!r})")
    hits = {tok for tok in re.findall(r"[A-Za-z_]+", cleaned.upper()) if tok in _FORBIDDEN_KEYWORDS}
    if hits:
        raise ReadOnlyViolation(f"forbidden keyword(s): {', '.join(sorted(hits))}")


def _strip_comments(sql: str) -> str:
    """Remove ``-- line`` and ``/* block */`` comments."""
    sql = re.sub(r"--[^\n]*", " ", sql)
    return re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)


def _mask_literals(sql: str) -> str:
    """Blank out string literals and quoted identifiers so keywords inside them do not count."""
    sql = re.sub(r"'(?:[^']|'')*'", "''", sql)
    return re.sub(r'"(?:[^"]|"")*"', '""', sql)
