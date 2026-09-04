"""``ulpf dlq`` — inspect and recover from the dead-letter queue.

Nothing that fails a pipeline stage is ever silently dropped (see
:mod:`ulpf.sinks.dlq`); it is written here instead, raw bytes and all. That
turns "the parser doesn't handle this yet" into a queue an operator can work
through rather than a quiet gap in the data:

* ``ulpf dlq stats``  — counts by reason and by stage. The reason with the
  highest count is where a new/fixed source definition (requirement e) would
  pay off first.
* ``ulpf dlq sample``  — the actual raw lines for one reason. This is exactly
  the input an operator needs to write (or fix) the YAML in
  ``configs/sources/`` — no guessing at the format from a description.
* ``ulpf dlq replay``  — once that YAML lands, re-run the affected dead
  letters through **today's** parse -> normalize -> enrich -> validate ->
  sink pipeline (the same reusable stages :mod:`ulpf.cli.reprocess` drives),
  exactly like ``ulpf reprocess`` does for already-normalized silver data, but
  starting from events that never made it out of the DLQ the first time. It
  never re-derives ``event_uid``/``raw_hash`` (requirement d) and prefers the
  bronze copy of the raw event over the one embedded in the dead letter, since
  bronze is the evidence tier (requirement a).

A dead letter that replays successfully is **marked resolved, never deleted or
rewritten** — :meth:`~ulpf.sinks.dlq.DeadLetterQueue.mark_resolved` appends a
resolution record to a second append-only file, so the original failure stays
in the audit trail even after it stops being current. A dead letter that fails
again (a different reason, or the same one) is left exactly as it was, and if
the pipeline dead-letters it again that is recorded as a brand-new entry, same
as any other pipeline failure.

USAGE
-----
    ulpf dlq stats
    ulpf dlq stats --json
    ulpf dlq sample --reason mapping_error -n 10
    ulpf dlq replay                          # every unresolved dead letter
    ulpf dlq replay --reason mapping_error
    ulpf dlq replay --since 2026-09-01
    ulpf dlq replay --dry-run                # preview only: nothing written,
                                              # nothing marked resolved
"""

from __future__ import annotations

import asyncio
import datetime as dt
import itertools
import json
import logging
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ulpf.config.settings import Settings, get_settings
from ulpf.core.models import DeadLetter, NormalizedEvent, RawEvent
from ulpf.enrich.factory import build_enrichment_pipeline
from ulpf.enrich.stage import EnrichStage
from ulpf.normalize.stage import NormalizeStage, ValidateStage
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.dlq import DeadLetterQueue
from ulpf.sinks.manager import SinkManager
from ulpf.sinks.raw_store import RawStore

_log = logging.getLogger(__name__)

dlq_app = typer.Typer(help="Inspect and recover from the dead-letter queue.", no_args_is_help=True)


def _load_settings() -> Settings:
    """Indirection so tests can point the commands at a temp configuration."""
    return get_settings()


def _parse_since(value: str | None) -> int | None:
    """Parse ``--since`` (``YYYY-MM-DD`` or full ISO-8601) to epoch nanoseconds."""
    if value is None:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise typer.BadParameter(f"--since must be YYYY-MM-DD or ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return int(parsed.timestamp() * 1_000_000_000)


def _isolated_dlq_settings(settings: Settings) -> Settings:
    """``--dry-run``: redirect any *new* dead letters to a throwaway directory."""
    scratch = Path(tempfile.mkdtemp(prefix="ulpf-dlq-replay-dry-run-dlq-"))
    return settings.model_copy(
        update={"storage": settings.storage.model_copy(update={"dlq_path": scratch})}
    )


def _raw_event_for(entry: DeadLetter, raw_store: RawStore) -> RawEvent:
    """Prefer the bronze copy (the evidence tier); fall back to the dead letter's own bytes."""
    return raw_store.read_by_uid(entry.event_uid) or RawEvent(
        event_uid=entry.event_uid,
        raw=entry.raw,
        raw_hash=entry.raw_hash,
        raw_len=len(entry.raw),
        ingest_time_ns=entry.ts_ns,
        source_id="dlq-replay",
        transport="file",
    )


# ======================================================================
# dlq replay
# ======================================================================


@dataclass
class ReplayReport:
    """The outcome of one ``ulpf dlq replay`` run."""

    reason: str | None
    since: str | None
    dry_run: bool
    candidates: int = 0
    succeeded: int = 0
    still_failing: int = 0
    written: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


async def run_replay(
    settings: Settings, *, reason: str | None, since: str | None, dry_run: bool
) -> ReplayReport:
    """Re-run every unresolved dead letter matching ``reason``/``since`` through the pipeline."""
    report = ReplayReport(reason=reason, since=since, dry_run=dry_run)
    dlq = DeadLetterQueue(settings)
    raw_store = RawStore(settings)
    registry = SourceRegistry()
    registry.load_all(settings.parse.sources_dir)
    coordinator = ParseCoordinator()

    dlq_settings = _isolated_dlq_settings(settings) if dry_run else settings
    normalize_stage = NormalizeStage(dlq_settings, registry)
    enrich_stage = EnrichStage(settings, build_enrichment_pipeline(settings))
    validate_stage = ValidateStage(dlq_settings, registry)
    sink_manager = None if dry_run else SinkManager.from_settings(settings)

    if sink_manager is not None:
        await sink_manager.start()
    try:
        since_ns = _parse_since(since)
        entries = dlq.iter_entries(reason=reason, since_ns=since_ns, unresolved_only=True)
        for entry in entries:
            report.candidates += 1
            resolved = await _replay_one(
                entry,
                raw_store=raw_store,
                coordinator=coordinator,
                normalize_stage=normalize_stage,
                enrich_stage=enrich_stage,
                validate_stage=validate_stage,
            )
            if resolved is None:
                report.still_failing += 1
                continue
            report.succeeded += 1
            if sink_manager is not None:
                delivered = await sink_manager.process(resolved)
                if delivered is not None:
                    report.written += 1
            if not dry_run:
                dlq.mark_resolved(
                    entry.event_uid,
                    detail={"original_reason": entry.reason, "original_stage": entry.stage},
                )
    finally:
        if sink_manager is not None:
            await sink_manager.flush()
    return report


async def _replay_one(
    entry: DeadLetter,
    *,
    raw_store: RawStore,
    coordinator: ParseCoordinator,
    normalize_stage: NormalizeStage,
    enrich_stage: EnrichStage,
    validate_stage: ValidateStage,
) -> NormalizedEvent | None:
    """Re-run one dead letter. Returns the normalized event on success, else ``None``."""
    raw_event = _raw_event_for(entry, raw_store)
    parsed = coordinator.parse(raw_event)  # same event_uid/raw_hash; no re-hash
    normalized = await normalize_stage.process(parsed)
    if normalized is None:
        return None  # still fails to map -> already dead-lettered again
    enriched = await enrich_stage.process(normalized)
    validated = await validate_stage.process(enriched)
    return validated  # None if validation still fails -> already dead-lettered again


def _render_replay(console: Console, report: ReplayReport) -> None:
    mode = "DRY RUN — nothing written, nothing marked resolved" if report.dry_run else "applied"
    scope_bits = [
        f"reason={report.reason}" if report.reason else None,
        f"since={report.since}" if report.since else None,
    ]
    scope = ", ".join(bit for bit in scope_bits if bit) or "all unresolved dead letters"
    console.print(
        Panel(f"scope: [cyan]{scope}[/]\nmode: {mode}", title="dlq replay", border_style="cyan")
    )

    table = Table(box=None, show_header=False)
    table.add_column(style="bold")
    table.add_column()
    table.add_row("candidates", str(report.candidates))
    table.add_row("succeeded", f"[green]{report.succeeded}[/]")
    table.add_row(
        "still failing", f"[red]{report.still_failing}[/]" if report.still_failing else "0"
    )
    table.add_row("written to sinks", "n/a (dry run)" if report.dry_run else str(report.written))
    console.print(table)


@dlq_app.command("replay")
def replay(
    reason: str | None = typer.Option(
        None, "--reason", help="Only dead letters with this exact reason."
    ),
    since: str | None = typer.Option(
        None, "--since", help="Only dead letters at/after this time (YYYY-MM-DD or ISO-8601)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Compute and report only; write and mark-resolved nothing."
    ),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Re-run dead letters through today's pipeline; mark successful replays resolved."""
    settings = _load_settings()
    report = asyncio.run(run_replay(settings, reason=reason, since=since, dry_run=dry_run))
    if json_out:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _render_replay(Console(), report)
    raise typer.Exit(code=0)


# ======================================================================
# dlq stats
# ======================================================================


@dlq_app.command("stats")
def stats(json_out: bool = typer.Option(False, "--json", help="Machine-readable output.")) -> None:
    """Dead-letter counts, grouped by reason and by stage."""
    settings = _load_settings()
    data = DeadLetterQueue(settings).stats()
    if json_out:
        typer.echo(json.dumps(data, indent=2))
        return
    console = Console()
    console.print(
        Panel(
            f"total [cyan]{data['total']}[/]  ·  "
            f"unresolved [yellow]{data['unresolved']}[/]  ·  resolved [green]{data['resolved']}[/]",
            title="dlq stats",
            border_style="cyan",
        )
    )
    _render_counts(console, "by reason", data["by_reason"])
    _render_counts(console, "by stage", data["by_stage"])


def _render_counts(console: Console, title: str, counts: dict[str, int]) -> None:
    table = Table(title=title, box=None)
    table.add_column("value", style="bold")
    table.add_column("count", justify="right")
    for key, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        table.add_row(key, str(count))
    if not counts:
        table.add_row("(none)", "0")
    console.print(table)


# ======================================================================
# dlq sample
# ======================================================================


@dlq_app.command("sample")
def sample(
    reason: str = typer.Option(..., "--reason", help="Only dead letters with this exact reason."),
    count: int = typer.Option(10, "-n", "--count", help="How many samples to print."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Print sample raw lines for one dead-letter reason — the input to writing a fix."""
    settings = _load_settings()
    dlq = DeadLetterQueue(settings)
    entries = list(itertools.islice(dlq.iter_entries(reason=reason), max(count, 0)))

    if json_out:
        typer.echo(
            json.dumps(
                [
                    {
                        "event_uid": entry.event_uid,
                        "stage": entry.stage,
                        "reason": entry.reason,
                        "detail": entry.detail,
                        "raw": entry.raw.decode("utf-8", errors="replace"),
                    }
                    for entry in entries
                ],
                indent=2,
            )
        )
        return

    console = Console()
    if not entries:
        console.print(f"[yellow]no dead letters with reason={reason!r}[/]")
        raise typer.Exit(code=0)
    for index, entry in enumerate(entries, start=1):
        body = entry.raw.decode("utf-8", errors="replace")
        if entry.detail:
            body += f"\n\n[dim]detail: {entry.detail}[/]"
        console.print(
            Panel(
                body,
                title=f"[{index}/{len(entries)}] {entry.event_uid}  stage={entry.stage}",
                border_style="yellow",
            )
        )
