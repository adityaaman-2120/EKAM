"""``ulpf compact`` — merge the silver tier's many small Parquet files.

Streaming writes leave thousands of tiny ``part-*.parquet`` files per partition
and query engines then spend their time opening files instead of reading data
(see :mod:`ulpf.sinks.compaction`). This command rewrites each partition into a
few ~128 MB files, losing no rows.

    ulpf compact                 # today's partitions (where small files pile up)
    ulpf compact --date 2026-09-01
    ulpf compact --all           # every partition under silver_path
    ulpf compact --all --json    # machine-readable
"""

from __future__ import annotations

import datetime as dt
import json

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ulpf.config.settings import Settings, get_settings
from ulpf.sinks.compaction import CompactionResult, Compactor


def _load_settings() -> Settings:
    """Indirection so tests can point the command at a temp configuration."""
    return get_settings()


def _human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def _render(console: Console, results: list[CompactionResult]) -> None:
    if not results:
        console.print(Panel("[yellow]No silver partitions to compact.[/]", title="compact",
                            border_style="yellow"))
        return

    table = Table(title="compaction", border_style="cyan")
    table.add_column("date")
    table.add_column("source_type", style="cyan")
    table.add_column("files", justify="right")
    table.add_column("rows", justify="right")
    table.add_column("size", justify="right")
    for r in results:
        arrow = "->" if r.compacted else "="
        files = f"{r.files_before} {arrow} {r.files_after}"
        size = f"{_human_bytes(r.bytes_before)} {arrow} {_human_bytes(r.bytes_after)}"
        style = "green" if r.compacted else "dim"
        table.add_row(r.date, r.source_type, f"[{style}]{files}[/]", f"{r.rows:,}", size)
    console.print(table)

    merged = sum(r.files_before - r.files_after for r in results if r.compacted)
    touched = sum(1 for r in results if r.compacted)
    console.print(Panel(
        f"[bold green]{touched} partition(s) compacted[/] · {merged} files removed",
        title="compact", border_style="green"))


def compact(
    date: str | None = typer.Option(None, "--date", help="Only compact this ingest date (YYYY-MM-DD)."),
    all_partitions: bool = typer.Option(False, "--all", help="Compact every partition under silver_path."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Merge the small Parquet files in each silver partition into a few large ones."""
    settings = _load_settings()
    compactor = Compactor(settings)

    if all_partitions:
        results = compactor.compact_all()
    elif date is not None:
        results = compactor.compact_all(date=date)
    else:
        results = compactor.compact_all(date=dt.datetime.now(dt.UTC).strftime("%Y-%m-%d"))

    if json_out:
        typer.echo(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        _render(Console(), results)
