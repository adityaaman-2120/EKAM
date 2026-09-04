"""``ulpf reprocess`` — replay bronze evidence through today's parser, not the one it arrived under.

THE OPERATIONAL STORY
----------------------
Perimeter parsers have bugs, and NTRO/SOC teams find them *after* logs have
already been ingested and normalized wrong. Most log pipelines treat that as a
write-off: the bad normalization is what shipped, and fixing the parser only
helps events from now on. ULPF does not have to make that trade, because of
three things this framework already guarantees:

* the raw bytes are preserved **losslessly** and never mutated — bronze, the
  evidence tier (requirement a);
* every raw event is **content-addressed** by its SHA-256 and a stable
  ``event_uid`` minted once at ingest (requirement d) — nothing about
  reprocessing needs, or is allowed, to re-derive either;
* onboarding a source is **just a YAML file** (requirement e), so a parser fix
  is a normal, versioned edit to that file, not a code change.

So when a parser bug is found and fixed, ``ulpf reprocess`` re-runs
**parse → normalize → enrich → validate → sink** for the affected raw events
against *today's* source definitions and writes corrected output to the silver
tier — it **never re-ingests and never re-hashes** (the bronze ``RawEvent`` is
read as-is; ``event_uid``/``raw_hash``/``ingest_time_ns`` travel through
unchanged), and it **never touches the signed integrity ledger** (that raw
evidence was already sealed once, at ingest; reprocessing must not mint a
second Merkle leaf for it). You correct history instead of losing it.

Corrected rows are stamped with a **new, distinguishable ``mapping_version``**
(``"<source_version>+reprocess-<run_id>"``, also written to
``metadata.log_version`` inside the OCSF record so it survives into the
flattened Parquet/ClickHouse columns) — old and new output for the same event
coexist in the lake and a query can tell them apart, or prefer the newest.

USAGE
-----
    ulpf reprocess --date 2026-09-04
    ulpf reprocess --date 2026-09-04 --source-type fortigate_traffic
    ulpf reprocess --date 2026-09-04 --dry-run       # compute + report, write nothing
    ulpf reprocess --date 2026-09-04 --compare        # also diff against the current silver rows
    ulpf reprocess --date 2026-09-04 --compare --json

``--dry-run`` touches nothing persistent: no sink writes (Parquet/ClickHouse/
OpenSearch/Splunk) and dead letters from this run go to a throwaway directory,
not the real DLQ — a true preview. ``--compare`` reads the *current* silver
rows for the same scope before writing anything new, and reports how many
events' core fields changed and how normalization completeness moved, per the
previous ``mapping_version`` (a prior reprocess run's output if there is one,
else the original ingest).
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import tempfile
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ulpf.config.settings import Settings, get_settings
from ulpf.core.models import NormalizedEvent, ParsedEvent, RawEvent
from ulpf.enrich.factory import build_enrichment_pipeline
from ulpf.enrich.stage import EnrichStage
from ulpf.normalize.ocsf import CLASS_REGISTRY
from ulpf.normalize.stage import NormalizeStage, ValidateStage
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.compaction import merge_tables
from ulpf.sinks.manager import SinkManager
from ulpf.sinks.parquet_sink import CORE_COLUMNS, core_row
from ulpf.sinks.raw_store import RawStore

_log = logging.getLogger(__name__)


def _load_settings() -> Settings:
    """Indirection so tests can point the command at a temp configuration."""
    return get_settings()


# ======================================================================
# reports
# ======================================================================


@dataclass
class CompareStats:
    """``--compare``: how the new output differs from what was in silver before this run."""

    no_previous: int = 0  # never written to silver before (nothing to compare against)
    changed: int = 0  # a core field differs from the previous silver row
    unchanged: int = 0  # core fields are identical to the previous silver row
    completeness_old_sum: float = 0.0
    completeness_new_sum: float = 0.0
    completeness_compared: int = 0  # events that had both an old and a new completeness score

    def to_dict(self) -> dict[str, Any]:
        return {
            "no_previous": self.no_previous,
            "changed": self.changed,
            "unchanged": self.unchanged,
            "completeness_old_avg": self.old_avg,
            "completeness_new_avg": self.new_avg,
            "completeness_delta_avg": self.delta_avg,
        }

    @property
    def old_avg(self) -> float | None:
        return self.completeness_old_sum / self.completeness_compared if self.completeness_compared else None

    @property
    def new_avg(self) -> float | None:
        return self.completeness_new_sum / self.completeness_compared if self.completeness_compared else None

    @property
    def delta_avg(self) -> float | None:
        if self.completeness_compared == 0:
            return None
        return self.new_avg - self.old_avg  # type: ignore[operator]


@dataclass
class ReprocessReport:
    """The outcome of one ``ulpf reprocess`` run."""

    date: str
    source_type: str | None
    dry_run: bool
    mapping_version_tag: str
    raw_events: int = 0
    in_scope: int = 0
    normalized: int = 0
    dead_lettered: int = 0
    written: int = 0
    compare: CompareStats | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["compare"] = self.compare.to_dict() if self.compare is not None else None
        return data


# ======================================================================
# core engine
# ======================================================================


async def run_reprocess(
    settings: Settings, *, date: str, source_type: str | None, dry_run: bool, compare: bool
) -> ReprocessReport:
    """Replay every bronze event for ``date`` (optionally scoped to ``source_type``)."""
    # a short random suffix guarantees two runs are always distinguishable even
    # if they land in the same wall-clock second
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    run_tag = f"reprocess-{timestamp}-{uuid.uuid4().hex[:6]}"
    report = ReprocessReport(date, source_type, dry_run, run_tag)
    if compare:
        report.compare = CompareStats()
        previous = _read_previous_rows(Path(settings.storage.silver_path), date, source_type)
    else:
        previous = {}

    dlq_settings = _isolated_dlq_settings(settings) if dry_run else settings
    registry = SourceRegistry()
    registry.load_all(settings.parse.sources_dir)
    coordinator = ParseCoordinator()
    normalize_stage = NormalizeStage(dlq_settings, registry)
    enrich_stage = EnrichStage(settings, build_enrichment_pipeline(settings))
    validate_stage = ValidateStage(dlq_settings, registry)
    sink_manager = None if dry_run else SinkManager.from_settings(settings)

    if sink_manager is not None:
        await sink_manager.start()
    try:
        for raw_event in RawStore(settings).iter_all(date):
            report.raw_events += 1
            status, normalized = await _reprocess_one(
                raw_event,
                coordinator=coordinator,
                registry=registry,
                normalize_stage=normalize_stage,
                enrich_stage=enrich_stage,
                validate_stage=validate_stage,
                source_type_filter=source_type,
                run_tag=run_tag,
            )
            if status == "out_of_scope":
                continue
            report.in_scope += 1
            if status == "dead_lettered":
                report.dead_lettered += 1
                continue
            assert normalized is not None
            report.normalized += 1

            if compare and report.compare is not None:
                _update_compare(report.compare, normalized, previous.get(normalized.event_uid))

            if sink_manager is not None:
                delivered = await sink_manager.process(normalized)
                if delivered is not None:
                    report.written += 1
    finally:
        if sink_manager is not None:
            await sink_manager.flush()
    return report


async def _reprocess_one(
    raw_event: RawEvent,
    *,
    coordinator: ParseCoordinator,
    registry: SourceRegistry,
    normalize_stage: NormalizeStage,
    enrich_stage: EnrichStage,
    validate_stage: ValidateStage,
    source_type_filter: str | None,
    run_tag: str,
) -> tuple[str, NormalizedEvent | None]:
    """Re-run one bronze event.

    Returns ``("out_of_scope", None)``, ``("dead_lettered", None)`` (already
    dead-lettered by ``normalize_stage``/``validate_stage``), or
    ``("ok", normalized_event)``.
    """
    parsed: ParsedEvent = coordinator.parse(raw_event)  # same event_uid/raw_hash; no re-hash
    definition = registry.match(parsed)
    matched_name = definition.name if definition is not None else "unknown"
    if source_type_filter is not None and matched_name != source_type_filter:
        return "out_of_scope", None

    normalized = await normalize_stage.process(parsed)
    if normalized is None:
        return "dead_lettered", None  # mapping failed -> already dead-lettered by NormalizeStage

    if definition is not None:
        tag = f"{definition.version}+{run_tag}"
        normalized.mapping_version = tag
        normalized.ocsf.setdefault("metadata", {})["log_version"] = tag

    enriched = await enrich_stage.process(normalized)
    validated = await validate_stage.process(enriched)
    if validated is None:
        return "dead_lettered", None  # validation failed -> already dead-lettered by ValidateStage
    return "ok", validated


def _isolated_dlq_settings(settings: Settings) -> Settings:
    """``--dry-run``: redirect dead letters to a throwaway directory (a true no-write preview)."""
    scratch = Path(tempfile.mkdtemp(prefix="ulpf-reprocess-dry-run-dlq-"))
    return settings.model_copy(
        update={"storage": settings.storage.model_copy(update={"dlq_path": scratch})}
    )


# ======================================================================
# --compare
# ======================================================================


def _read_previous_rows(
    silver_path: Path, date: str, source_type: str | None
) -> dict[str, dict[str, Any]]:
    """``event_uid -> its current silver row`` for this scope, before this run writes anything.

    When an event has more than one existing row (an earlier reprocess run left
    its output alongside the original), the row with the newest
    ``metadata.log_version`` wins — that is the most recent prior state.
    """
    date_dir = silver_path / f"date={date}"
    if not date_dir.is_dir():
        return {}
    source_dirs = (
        [date_dir / f"source_type={source_type}"]
        if source_type is not None
        else sorted(p for p in date_dir.glob("source_type=*") if p.is_dir())
    )
    files = [path for directory in source_dirs for path in sorted(directory.glob("part-*.parquet"))]
    if not files:
        return {}

    merged = merge_tables([pq.ParquetFile(path).read() for path in files])
    by_uid: dict[str, dict[str, Any]] = {}
    for row in merged.to_pylist():
        uid = row.get("event_uid")
        if not uid:
            continue
        current = by_uid.get(uid)
        if current is None or _log_version_rank(row) >= _log_version_rank(current):
            by_uid[uid] = row
    return by_uid


def _log_version_rank(row: dict[str, Any]) -> tuple[int, str]:
    """Sort key preferring a real (reprocessed) ``metadata.log_version`` over none, then latest.

    Ranks by the embedded ``run_tag`` (``reprocess-<timestamp>-<rand>``), not the
    full ``"<source_version>+<run_tag>"`` string, so recency ordering does not
    depend on the source definition's version string being lexicographically
    (i.e. semver-) comparable.
    """
    tag = row.get("metadata.log_version")
    if not isinstance(tag, str) or not tag:
        return (0, "")
    return (1, tag.rsplit("+", 1)[-1])


def _update_compare(
    stats: CompareStats, normalized: NormalizedEvent, previous_row: dict[str, Any] | None
) -> None:
    """Diff the freshly reprocessed event against its previous silver row, if any."""
    new_completeness = OcsfValidator(record_metrics=False).validate(normalized.ocsf).completeness
    if previous_row is None:
        stats.no_previous += 1
        return

    new_core = core_row(normalized)
    if any(new_core.get(column) != previous_row.get(column) for column in CORE_COLUMNS):
        stats.changed += 1
    else:
        stats.unchanged += 1

    old_class_uid = previous_row.get("class_uid")
    old_completeness = _flat_completeness(previous_row, old_class_uid)
    if old_completeness is not None:
        stats.completeness_old_sum += old_completeness
        stats.completeness_new_sum += new_completeness
        stats.completeness_compared += 1


def _flat_completeness(row: dict[str, Any], class_uid: Any) -> float | None:
    """Re-derive :attr:`OcsfValidator`'s completeness score from a flat silver row.

    Silver stores the OCSF record flattened to dotted columns (plus the 17
    renamed core ones), so an attribute is "populated" the same way
    :class:`~ulpf.normalize.validator.OcsfValidator` decides it: present
    directly, or (for an object attribute like ``src_endpoint``) any
    ``"<attr>."``-prefixed column has a value.
    """
    module = CLASS_REGISTRY.get(int(class_uid)) if isinstance(class_uid, (int, float)) else None
    if module is None:
        return None
    shape = module.CLASS_SHAPE
    attrs = list(dict.fromkeys([*shape["required"], *shape["recommended"]]))
    if not attrs:
        return None
    populated = sum(1 for attr in attrs if _attr_populated(row, attr))
    return populated / len(attrs)


def _attr_populated(row: dict[str, Any], attr: str) -> bool:
    """Whether ``attr`` has data in a flat silver row (scalar column or any ``attr.*`` column)."""
    if attr in ("unmapped", "enrichments"):
        value = row.get(f"{attr}_json")
        return value not in (None, "", "{}")
    direct = row.get(attr)
    if direct not in (None, ""):
        return True
    prefix = f"{attr}."
    return any(value not in (None, "") for key, value in row.items() if key.startswith(prefix))


# ======================================================================
# CLI
# ======================================================================


def _render(console: Console, report: ReprocessReport) -> None:
    mode = "DRY RUN — nothing written" if report.dry_run else "applied"
    scope = report.source_type or "all sources"
    console.print(Panel(
        f"date [cyan]{report.date}[/]  ·  scope [cyan]{scope}[/]  ·  {mode}\n"
        f"mapping_version tag: [cyan]{report.mapping_version_tag}[/]",
        title="reprocess", border_style="cyan"))

    table = Table(box=None, show_header=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("raw events read", str(report.raw_events))
    table.add_row("in scope", str(report.in_scope))
    table.add_row("normalized", f"[green]{report.normalized}[/]")
    table.add_row("dead-lettered", f"[red]{report.dead_lettered}[/]" if report.dead_lettered else "0")
    table.add_row("written to sinks", "n/a (dry run)" if report.dry_run else str(report.written))
    console.print(table)

    if report.compare is not None:
        compare = report.compare
        ctable = Table(title="compare vs. previous mapping_version", box=None, show_header=False)
        ctable.add_column(style="bold")
        ctable.add_column()
        ctable.add_row("changed", f"[yellow]{compare.changed}[/]")
        ctable.add_row("unchanged", str(compare.unchanged))
        ctable.add_row("no previous data", str(compare.no_previous))
        old = f"{compare.old_avg * 100:.1f}%" if compare.old_avg is not None else "n/a"
        new = f"{compare.new_avg * 100:.1f}%" if compare.new_avg is not None else "n/a"
        delta = f"{compare.delta_avg * 100:+.1f}pp" if compare.delta_avg is not None else "n/a"
        ctable.add_row("completeness (old -> new)", f"{old} -> {new}  ({delta})")
        console.print(ctable)


def reprocess(
    date: str = typer.Option(..., "--date", help="Ingest date to reprocess (YYYY-MM-DD)."),
    source_type: str | None = typer.Option(
        None, "--source-type", help="Only this source's events (matched against today's definitions)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Compute and report only; write nothing (not even to the DLQ)."
    ),
    compare: bool = typer.Option(
        False, "--compare", help="Diff the new output against the current silver rows for this scope."
    ),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Re-run parse, normalize, enrich, validate and sink for one date's bronze evidence."""
    settings = _load_settings()
    report = asyncio.run(
        run_reprocess(settings, date=date, source_type=source_type, dry_run=dry_run, compare=compare)
    )
    if json_out:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _render(Console(), report)
    raise typer.Exit(code=0)
