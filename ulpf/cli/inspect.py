"""``ulpf inspect`` — trace one raw log line through the whole pipeline.

A debugging aid for onboarding a new perimeter-log source: it takes a single
raw line (``--line``) or the first few lines of a file (``--file``/``--limit``)
and prints, stage by stage, exactly what ULPF would do with it:

1. **RAW** — the original bytes, their SHA-256, and the minted ``event_uid``.
2. **SNIFF** — the ``(outer, inner)`` formats format detection reports.
3. **MATCH** — which :class:`~ulpf.parse.dsl.schema.SourceDefinition` matched
   (name / version / product_version), or ``no match`` plus a ``parse_note``
   explaining why the line did not reach a normalized record.
4. **PARSED** — the flat field dict the parse engine produced.
5. **NORMALIZED** — the finalized OCSF record, pretty-printed.
6. **VALIDATION** — ``valid`` true/false, any errors, and the completeness KPI
   as a percentage.
7. **UNMAPPED** — the keys parked in ``ocsf["unmapped"]`` and their count.
8. **CROSSWALK** — the ECS document and CIM field set (only with ``--crosswalk``).

``--json`` emits the whole report as JSON (one object per line); ``--quiet``
prints only the OCSF record. Colour: green for a valid record, red for
validation errors, yellow for unmapped keys.
"""

from __future__ import annotations

import json as _json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table

from ulpf.config.settings import get_settings
from ulpf.core.errors import ParseError, UlpfError
from ulpf.core.models import RawEvent
from ulpf.detect.sniffer import sniff_layered
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.crosswalk.cim import to_cim
from ulpf.normalize.crosswalk.ecs import to_ecs
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.decode import decode_raw, strip_bom_bytes
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import SourceDefinition
from ulpf.parse.engines.util import flatten
from ulpf.parse.registry import registry as _engine_registry
from ulpf.parse.syslog_envelope import parse_syslog_envelope

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SOURCE_ID = "inspect"


# --------------------------------------------------------------------------
# wiring


def _resolve_sources_dir(explicit: Path | None) -> Path:
    """Pick the source-definition directory: the flag, else the configured path."""
    if explicit is not None:
        return explicit
    configured = get_settings().parse.sources_dir
    if configured.is_absolute():
        return configured
    for base in (Path.cwd(), _REPO_ROOT):
        if (base / configured).is_dir():
            return base / configured
    return configured


def _load_registry(sources_dir: Path) -> SourceRegistry:
    """Load every ``*.yaml`` under ``sources_dir`` into a fresh registry."""
    registry = SourceRegistry()
    if sources_dir.is_dir():
        registry.load_all(sources_dir)
    return registry


def _read_lines(path: Path, limit: int) -> list[str]:
    """Return up to ``limit`` non-blank lines from ``path``."""
    out: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            out.append(line)
        if len(out) >= limit:
            break
    return out


# --------------------------------------------------------------------------
# the pipeline trace


def build_report(raw: bytes, registry: SourceRegistry, *, with_crosswalk: bool) -> dict[str, Any]:
    """Run one raw line through detect -> parse -> match -> normalize -> validate."""
    event = make_raw_event(raw, source_id=_SOURCE_ID, transport="file")
    text, bom_stripped = decode_raw(raw)
    outer, inner = sniff_layered(text)

    parsed_fields, parse_error = _coordinator_fields(event)
    definition = _match(registry, event, parsed_fields, parse_error)

    fields, field_error = parsed_fields, parse_error
    if definition is not None:
        fields, field_error = _definition_fields(event, definition)

    ocsf, norm_error = _normalize(definition, fields, event, parseable=parse_error is None)
    report: dict[str, Any] = {
        "raw": _raw_section(event, text, bom_stripped=bom_stripped),
        "sniff": {"outer": outer, "inner": inner},
        "match": _match_section(definition, inner, fields, field_error or norm_error),
        "parsed": fields if parse_error is None or definition is not None else None,
        "normalized": ocsf,
        "validation": _validation_section(definition, ocsf, norm_error),
        "unmapped": _unmapped_section(ocsf),
    }
    if with_crosswalk:
        report["crosswalk"] = (
            {"ecs": to_ecs(ocsf), "cim": to_cim(ocsf)} if ocsf is not None else None
        )
    return report


def _coordinator_fields(event: RawEvent) -> tuple[dict[str, Any], ParseError | None]:
    """Sniffed-format parse via :class:`ParseCoordinator`; ``{}`` + error on failure."""
    try:
        return dict(ParseCoordinator().parse(event).fields), None
    except ParseError as exc:
        return {}, exc


def _match(
    registry: SourceRegistry,
    event: RawEvent,
    fields: dict[str, Any],
    parse_error: ParseError | None,
) -> SourceDefinition | None:
    """Find the source definition whose ``detect`` rules match this line."""
    text, _ = decode_raw(event.raw)
    if parse_error is None:
        return registry.match_text(text, fields)
    return registry.match_text(text, {})


def _definition_fields(
    event: RawEvent, definition: SourceDefinition
) -> tuple[dict[str, Any], ParseError | None]:
    """Parse the line with the matched definition's declared engine + options."""
    _engine_registry.load_engine_modules()
    spec = definition.parse
    text, bom_stripped = decode_raw(event.raw)
    raw_bytes = strip_bom_bytes(event.raw) if bom_stripped else event.raw
    envelope: dict[str, Any] = {}
    payload = text
    if spec.envelope == "syslog":
        envelope, message = parse_syslog_envelope(raw_bytes)
        payload = (
            text if spec.engine in ("cef", "leef") else message.decode("utf-8", errors="replace")
        )
    try:
        fields = dict(_engine_registry.get(spec.engine).parse(payload, spec.options))
    except (UlpfError, ValueError, KeyError) as exc:
        note = exc.detail if isinstance(exc, UlpfError) else {"error": str(exc)}
        return {}, ParseError(f"{spec.engine} engine failed", detail=dict(note))
    if envelope:
        fields.update(flatten(envelope, prefix="envelope"))
    return fields, None


def _normalize(
    definition: SourceDefinition | None,
    fields: dict[str, Any],
    event: RawEvent,
    *,
    parseable: bool,
) -> tuple[dict[str, Any] | None, UlpfError | None]:
    """Map to OCSF when a source matched, else a passthrough record (or ``None``)."""
    if definition is not None:
        try:
            mapped = Mapper().to_ocsf(
                definition, fields, event_uid=event.event_uid, raw_hash=event.raw_hash
            )
            return finalize(mapped), None
        except UlpfError as exc:
            return None, exc
    if not parseable and not fields:
        return None, None
    return {
        "metadata": {"uid": event.event_uid, "log_hash": event.raw_hash},
        "unmapped": dict(fields),
    }, None


# --------------------------------------------------------------------------
# report sections (plain data, shared by rich / json / quiet output)


def _raw_section(event: RawEvent, text: str, *, bom_stripped: bool) -> dict[str, Any]:
    """The RAW section: bytes, hash (over the original bytes), and the event uid."""
    return {
        "text": text,
        "bytes": event.raw_len,
        "sha256": event.raw_hash,
        "event_uid": event.event_uid,
        "bom_stripped": bom_stripped,
    }


_BULKY_DETAIL_KEYS = ("parsed_fields", "partial_ocsf")


def _parse_note(inner_format: str, fields: dict[str, Any], error: UlpfError | None) -> str:
    """Why the line produced no matched-and-mapped OCSF record."""
    if error is not None:
        detail = {k: v for k, v in error.detail.items() if k not in _BULKY_DETAIL_KEYS}
        return f"{type(error).__name__}: {detail or error.message}"
    parts = [f"inner format sniffed as {inner_format!r}", f"{len(fields)} field(s) extracted"]
    parts.append("no source definition's detect rules matched")
    return "; ".join(parts)


def _match_section(
    definition: SourceDefinition | None,
    inner_format: str,
    fields: dict[str, Any],
    error: UlpfError | None,
) -> dict[str, Any]:
    """The MATCH section: the matched definition, or ``no match`` + a note."""
    if definition is None:
        return {"matched": False, "parse_note": _parse_note(inner_format, fields, error)}
    section: dict[str, Any] = {
        "matched": True,
        "name": definition.name,
        "version": definition.version,
        "product_version": definition.product_version,
    }
    if error is not None:
        section["parse_note"] = _parse_note(inner_format, fields, error)
    return section


def _validation_section(
    definition: SourceDefinition | None,
    ocsf: dict[str, Any] | None,
    norm_error: UlpfError | None,
) -> dict[str, Any] | None:
    """The VALIDATION section: valid flag, errors, warnings, completeness %."""
    if norm_error is not None:
        return {
            "valid": False,
            "errors": [f"{type(norm_error).__name__}: {norm_error}"],
            "warnings": [],
            "completeness_pct": 0.0,
        }
    if definition is None or ocsf is None:
        return None
    result = OcsfValidator(record_metrics=False).validate(ocsf)
    return {
        "valid": result.valid,
        "errors": result.errors,
        "warnings": result.warnings,
        "completeness_pct": round(result.completeness * 100, 1),
    }


def _unmapped_section(ocsf: dict[str, Any] | None) -> dict[str, Any]:
    """The UNMAPPED section: the keys held in ``ocsf['unmapped']`` and their count."""
    unmapped = ocsf.get("unmapped") if isinstance(ocsf, dict) else None
    if not isinstance(unmapped, dict):
        unmapped = {}
    return {"count": len(unmapped), "keys": sorted(unmapped), "values": dict(unmapped)}


# --------------------------------------------------------------------------
# rich rendering


def _json_block(obj: Any) -> JSON:
    """A rich-highlighted JSON renderable for a dict/list."""
    return JSON(_json.dumps(obj, default=str, sort_keys=True))


def _raw_panel(raw: dict[str, Any]) -> Panel:
    """Render section 1 (RAW)."""
    bom = (
        "\n[yellow]bom[/]       leading BOM stripped before detection"
        if raw["bom_stripped"]
        else ""
    )
    body = (
        f"[dim]bytes     [/] {raw['bytes']}\n"
        f"[dim]sha256    [/] {raw['sha256']}\n"
        f"[dim]event_uid [/] {raw['event_uid']}{bom}\n\n"
        f"{raw['text']}"
    )
    return Panel(body, title="1 . RAW", border_style="cyan")


def _match_panel(match: dict[str, Any]) -> Panel:
    """Render section 3 (MATCH), green on a hit and red on a miss."""
    if match["matched"]:
        lines = [
            f"[green]matched[/] [bold]{match['name']}[/]",
            f"[dim]version[/]          {match['version']}",
            f"[dim]product_version[/]  {match['product_version']}",
        ]
        if "parse_note" in match:
            lines.append(f"[red]parse_note[/] {match['parse_note']}")
        return Panel("\n".join(lines), title="3 . MATCH", border_style="green")
    body = f"[red]no match[/]\n[dim]parse_note[/] {match['parse_note']}"
    return Panel(body, title="3 . MATCH", border_style="red")


def _parsed_panel(fields: dict[str, Any] | None) -> Panel:
    """Render section 4 (PARSED) as a field/value table."""
    if not fields:
        return Panel("[dim]no fields extracted[/]", title="4 . PARSED", border_style="blue")
    table = Table(show_header=True, header_style="bold", box=None, expand=True)
    table.add_column("field", no_wrap=True)
    table.add_column("value", overflow="fold")
    for key in sorted(fields):
        table.add_row(key, str(fields[key]))
    return Panel(table, title="4 . PARSED", border_style="blue")


def _normalized_panel(ocsf: dict[str, Any] | None) -> Panel:
    """Render section 5 (NORMALIZED) as pretty JSON."""
    if ocsf is None:
        return Panel("[red]no OCSF record produced[/]", title="5 . NORMALIZED", border_style="red")
    return Panel(_json_block(ocsf), title="5 . NORMALIZED", border_style="magenta")


def _validation_panel(validation: dict[str, Any] | None) -> Panel:
    """Render section 6 (VALIDATION): green when valid, red when it has errors."""
    if validation is None:
        return Panel(
            "[dim]not validated (no OCSF class assigned)[/]",
            title="6 . VALIDATION",
            border_style="yellow",
        )
    head = "[green]valid: true[/]" if validation["valid"] else "[red]valid: false[/]"
    lines = [head, f"completeness: [bold]{validation['completeness_pct']}%[/]"]
    lines += [f"[red]error:[/] {err}" for err in validation["errors"]]
    lines += [f"[yellow]warn:[/] {warn}" for warn in validation["warnings"]]
    return Panel(
        "\n".join(lines),
        title="6 . VALIDATION",
        border_style="green" if validation["valid"] else "red",
    )


def _unmapped_panel(unmapped: dict[str, Any]) -> Panel:
    """Render section 7 (UNMAPPED), yellow whenever any key is unmapped."""
    if unmapped["count"] == 0:
        return Panel("[green]0 unmapped keys[/]", title="7 . UNMAPPED", border_style="green")
    body = f"[yellow]{unmapped['count']} unmapped key(s)[/]\n" + ", ".join(unmapped["keys"])
    return Panel(body, title="7 . UNMAPPED", border_style="yellow")


def _crosswalk_panel(crosswalk: dict[str, Any] | None) -> Panel:
    """Render section 8 (CROSSWALK): the ECS document and CIM field set."""
    if not crosswalk:
        return Panel(
            "[dim]no crosswalk (no OCSF record)[/]", title="8 . CROSSWALK", border_style="cyan"
        )
    grid = Table.grid(padding=(0, 2))
    grid.add_column()
    grid.add_row("[bold]ECS[/]")
    grid.add_row(_json_block(crosswalk["ecs"]))
    grid.add_row("[bold]CIM[/]")
    grid.add_row(_json_block(crosswalk["cim"]))
    return Panel(grid, title="8 . CROSSWALK", border_style="cyan")


def _sniff_panel(sniff: dict[str, str], *, matched: bool) -> Panel:
    """Render section 2 (SNIFF).

    A bare ``unknown`` inner format reads like a failure, but for grok- and
    dissect-based sources (Cisco ASA, iptables, ...) it is the expected path:
    format detection cannot classify the body, yet a source definition's own
    pattern still parses it. Say so when a source matched.
    """
    inner = f"[bold]{sniff['inner']}[/]"
    if sniff["inner"] == "unknown" and matched:
        inner += " [dim](handled by source pattern)[/]"
    return Panel(
        f"outer [bold]{sniff['outer']}[/]   ->   inner {inner}",
        title="2 . SNIFF",
        border_style="cyan",
    )


def _render(console: Console, report: dict[str, Any], *, with_crosswalk: bool) -> None:
    """Print every section of one report to ``console``."""
    console.print(_raw_panel(report["raw"]))
    console.print(_sniff_panel(report["sniff"], matched=report["match"]["matched"]))
    console.print(_match_panel(report["match"]))
    console.print(_parsed_panel(report["parsed"]))
    console.print(_normalized_panel(report["normalized"]))
    console.print(_validation_panel(report["validation"]))
    console.print(_unmapped_panel(report["unmapped"]))
    if with_crosswalk:
        console.print(_crosswalk_panel(report.get("crosswalk")))


# --------------------------------------------------------------------------
# the command


def inspect(
    line: str | None = typer.Option(None, "--line", "-l", help="A single raw log line."),
    file: Path | None = typer.Option(
        None,
        "--file",
        "-f",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Read raw log lines from this file.",
    ),
    limit: int = typer.Option(5, "--limit", "-n", min=1, help="Max lines to read from --file."),
    sources: Path | None = typer.Option(
        None, "--sources", help="Source-definition directory (default: configured sources_dir)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit the full report as JSON."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Print only the OCSF record."),
    crosswalk: bool = typer.Option(
        False, "--crosswalk", help="Also show the ECS and CIM projections."
    ),
) -> None:
    """Trace raw log line(s) through detect, parse, match, normalize and validate."""
    if (line is None) == (file is None):
        raise typer.BadParameter("provide exactly one of --line or --file")
    if as_json and quiet:
        raise typer.BadParameter("--json and --quiet are mutually exclusive")

    lines = [line] if line is not None else _read_lines(file, limit)  # type: ignore[arg-type]
    if not lines:
        raise typer.BadParameter("no non-blank lines to inspect")
    registry = _load_registry(_resolve_sources_dir(sources))
    console = Console()
    for index, one in enumerate(lines, start=1):
        report = build_report(one.encode("utf-8"), registry, with_crosswalk=crosswalk)
        _emit(console, report, index, len(lines), as_json=as_json, quiet=quiet, crosswalk=crosswalk)


def _emit(
    console: Console,
    report: dict[str, Any],
    index: int,
    total: int,
    *,
    as_json: bool,
    quiet: bool,
    crosswalk: bool,
) -> None:
    """Write one report in the requested output mode."""
    if as_json:
        typer.echo(_json.dumps(report, indent=2, default=str))
        return
    if quiet:
        typer.echo(_json.dumps(report["normalized"], indent=2, default=str))
        return
    if total > 1:
        console.rule(f"line {index}/{total}")
    _render(console, report, with_crosswalk=crosswalk)
