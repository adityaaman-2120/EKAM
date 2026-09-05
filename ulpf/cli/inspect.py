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
6. **ENRICHMENT** — runs the *live* enrichment chain (network context, GeoIP,
   threat intel, ATT&CK) over the normalized record: which enrichers produced
   output, which are disabled and why, per-enricher latency, and the merged
   ``enrichments`` dict. Comes between NORMALIZED and VALIDATION, as in the
   real pipeline.
7. **VALIDATION** — ``valid`` true/false, any errors, and the completeness KPI
   as a percentage.
8. **UNMAPPED** — the keys parked in ``ocsf["unmapped"]`` and their count.
9. **CROSSWALK** — the ECS document and CIM field set (only with ``--crosswalk``).

``--json`` emits the whole report as JSON (one object per line); ``--quiet``
prints only the OCSF record. Colour: green for a valid record, red for
validation errors, yellow for unmapped keys.
"""

from __future__ import annotations

import contextlib
import json as _json
import logging
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table

from ulpf.config.settings import Settings, get_settings
from ulpf.core.errors import ParseError, UlpfError
from ulpf.core.models import RawEvent
from ulpf.detect.sniffer import sniff_layered
from ulpf.enrich.factory import ENRICHER_ORDER, build_enrichers
from ulpf.enrich.stage import promote_enrichments
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.crosswalk.cim import to_cim
from ulpf.normalize.crosswalk.ecs import to_ecs
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.coordinator import ParseCoordinator, parse_for_definition
from ulpf.parse.decode import decode_raw
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import SourceDefinition

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
    # Run the live enrichment chain over ``ocsf`` (mutates it, exactly like the
    # pipeline's EnrichStage) so NORMALIZED and VALIDATION reflect the enriched
    # record — enrichment happens between normalize and validate.
    enrichment = _enrichment_section(ocsf, _enrich_settings())
    report: dict[str, Any] = {
        "raw": _raw_section(event, text, bom_stripped=bom_stripped),
        "sniff": {"outer": outer, "inner": inner},
        "match": _match_section(definition, inner, fields, field_error or norm_error),
        "parsed": fields if parse_error is None or definition is not None else None,
        "normalized": ocsf,
        "enrichment": enrichment,
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
    """Parse the line with the matched definition's declared engine + options.

    Delegates to :func:`~ulpf.parse.coordinator.parse_for_definition` — the
    same authoritative reparse :class:`~ulpf.normalize.stage.NormalizeStage`
    uses in the live pipeline, so ``inspect`` can never again show a result
    the running system would not actually produce.
    """
    try:
        return parse_for_definition(event.raw, definition), None
    except ParseError as exc:
        return {}, exc


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
# enrichment (the live chain — same enrichers, order, merge and promotion as
# ``ulpf.enrich.stage.EnrichStage``; the hot-path thread-pool timeout wrapper is
# skipped since inspect is not the hot path)


def _enrich_settings() -> Settings:
    """Settings with the enrichment config paths resolved to absolute (like --sources)."""
    settings = get_settings()
    enrich = settings.enrich
    updates: dict[str, Any] = {
        "assets_path": _resolve_repo_path(enrich.assets_path),
        "attack_map_path": _resolve_repo_path(enrich.attack_map_path),
        "ioc_dir": _resolve_repo_path(enrich.ioc_dir),
    }
    for attr in ("geoip_db_path", "geoip_asn_db_path"):
        value = getattr(enrich, attr)
        if value is not None:
            updates[attr] = _resolve_repo_path(value)
    return settings.model_copy(update={"enrich": enrich.model_copy(update=updates)})


def _resolve_repo_path(path: Path) -> Path:
    """Resolve a config-relative path against the CWD, then the repo root."""
    if path.is_absolute():
        return path
    for base in (Path.cwd(), _REPO_ROOT):
        if (base / path).exists():
            return base / path
    return _REPO_ROOT / path


@contextlib.contextmanager
def _quiet_enrich_logs() -> Iterator[None]:
    """Silence the enrichers' operational WARNINGs (e.g. 'geoip disabled').

    ``inspect`` reports every enricher's status inside the ENRICHMENT panel, so
    those log lines would only clutter the top of the output.
    """
    log = logging.getLogger("ulpf.enrich")
    prior = log.level
    log.setLevel(logging.ERROR)
    try:
        yield
    finally:
        log.setLevel(prior)


def _enrichment_section(ocsf: dict[str, Any] | None, settings: Settings) -> dict[str, Any]:
    """Run every enricher over ``ocsf`` (mutated in place); return the ENRICHMENT data."""
    if not isinstance(ocsf, dict) or "class_uid" not in ocsf:
        return {
            "ran": False,
            "reason": "no OCSF record to enrich",
            "enrichers": [],
            "enrichments": {},
        }

    master_on = settings.enrich.enabled
    rows: list[dict[str, Any]] = []
    merged: dict[str, Any] = dict(ocsf.get("enrichments") or {})
    with _quiet_enrich_logs():
        chain = build_enrichers(settings) if master_on else []
        built = {getattr(e, "name", ""): e for e in chain}
        for name in ENRICHER_ORDER:
            row = _run_enricher(name, built.get(name), ocsf, settings, master_on=master_on)
            rows.append(row)
            if row["output"]:
                merged.update(row["output"])
    if merged:
        ocsf["enrichments"] = merged
        promote_enrichments(ocsf, merged)
    return {
        "ran": master_on,
        "reason": None if master_on else "settings.enrich.enabled is false",
        "enrichers": rows,
        "enrichments": merged,
    }


def _run_enricher(
    name: str, enricher: Any, ocsf: dict[str, Any], settings: Settings, *, master_on: bool
) -> dict[str, Any]:
    """Time one enricher and classify it: produced / no_match / disabled / error."""
    base: dict[str, Any] = {"name": name, "status": "disabled", "reason": None}
    base |= {"latency_ms": 0.0, "output": {}}
    if not master_on:
        return {**base, "reason": "settings.enrich.enabled is false"}
    if not getattr(settings.enrich, name, False) or enricher is None:
        return {**base, "reason": f"settings.enrich.{name} is false"}
    self_disabled = _self_disabled_reason(name, enricher, settings)
    if self_disabled is not None:
        return {**base, "reason": self_disabled}

    start = time.perf_counter()
    try:
        out = enricher.enrich(dict(ocsf))
    except Exception as exc:  # noqa: BLE001 - a bad enricher must never break inspect
        return {
            **base,
            "status": "error",
            "reason": f"{type(exc).__name__}: {exc}",
            "latency_ms": round((time.perf_counter() - start) * 1000, 3),
        }
    latency_ms = round((time.perf_counter() - start) * 1000, 3)
    out = out if isinstance(out, dict) else {}
    status, note = ("produced", None) if out else ("no_match", _readiness_note(enricher))
    return {
        "name": name,
        "status": status,
        "reason": note,
        "latency_ms": latency_ms,
        "output": out,
    }


def _self_disabled_reason(name: str, enricher: Any, settings: Settings) -> str | None:
    """Why an *enabled* enricher has self-disabled (currently only GeoIP, no database)."""
    if name == "geoip" and getattr(enricher, "enabled", True) is False:
        path = settings.enrich.geoip_db_path
        if path is None:
            return (
                "no database configured (settings.enrich.geoip_db_path is null; "
                "see deploy/data/README.md)"
            )
        return f"no database at {path}"
    return None


def _readiness_note(enricher: Any) -> str | None:
    """The enricher's own 'why nothing can match' detail when it isn't ready."""
    if not hasattr(enricher, "describe"):
        return None
    info: dict[str, Any] = enricher.describe()
    return info.get("detail") if info.get("ready") is False else None


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
            title="7 . VALIDATION",
            border_style="yellow",
        )
    head = "[green]valid: true[/]" if validation["valid"] else "[red]valid: false[/]"
    lines = [head, f"completeness: [bold]{validation['completeness_pct']}%[/]"]
    lines += [f"[red]error:[/] {err}" for err in validation["errors"]]
    lines += [f"[yellow]warn:[/] {warn}" for warn in validation["warnings"]]
    return Panel(
        "\n".join(lines),
        title="7 . VALIDATION",
        border_style="green" if validation["valid"] else "red",
    )


def _unmapped_panel(unmapped: dict[str, Any]) -> Panel:
    """Render section 7 (UNMAPPED), yellow whenever any key is unmapped."""
    if unmapped["count"] == 0:
        return Panel("[green]0 unmapped keys[/]", title="8 . UNMAPPED", border_style="green")
    body = f"[yellow]{unmapped['count']} unmapped key(s)[/]\n" + ", ".join(unmapped["keys"])
    return Panel(body, title="8 . UNMAPPED", border_style="yellow")


_ENRICH_STATUS_STYLE = {
    "produced": "green",
    "no_match": "dim",
    "disabled": "yellow",
    "error": "red",
}


def _enrichment_output_keys(output: dict[str, Any], *, limit: int = 4) -> str:
    """A compact hint at what an enricher produced (its namespace's inner keys)."""
    inner = next(iter(output.values())) if len(output) == 1 else output
    keys = sorted(inner) if isinstance(inner, dict) else sorted(output)
    shown = ", ".join(keys[:limit])
    return f"{shown}, +{len(keys) - limit} more" if len(keys) > limit else shown


def _enrichment_row_line(row: dict[str, Any]) -> str:
    """One coloured line describing a single enricher's outcome."""
    style = _ENRICH_STATUS_STYLE.get(row["status"], "dim")
    name = f"[{style}]{row['name']:<15}[/]"
    latency = f"[dim]{row['latency_ms']:.3f} ms[/]"
    if row["status"] == "produced":
        keys = _enrichment_output_keys(row["output"])
        return f"{name} [green]produced[/]  [dim]{keys}[/]  {latency}"
    if row["status"] == "disabled":
        return f"{name} [yellow]disabled[/]: {row['reason']}"
    if row["status"] == "error":
        return f"{name} [red]error[/]: {row['reason']}  {latency}"
    tail = f" [dim]({row['reason']})[/]" if row["reason"] else ""
    return f"{name} [dim]enabled, no match[/]{tail}  {latency}"


def _enrichment_panel(enrichment: dict[str, Any]) -> Panel:
    """Render section 8 (ENRICHMENT): per-enricher status + latency + merged output."""
    rows = enrichment["enrichers"]
    if not rows:
        return Panel(
            f"[dim]not run — {enrichment['reason']}[/]",
            title="6 . ENRICHMENT",
            border_style="yellow",
        )
    grid = Table.grid(padding=(0, 0))
    grid.add_column()
    grid.add_row("\n".join(_enrichment_row_line(row) for row in rows))
    grid.add_row("")
    grid.add_row(
        _json_block(enrichment["enrichments"])
        if enrichment["enrichments"]
        else "[dim]merged enrichments: {} (nothing produced)[/]"
    )
    if any(r["status"] == "error" for r in rows):
        border = "red"
    elif any(r["status"] == "produced" for r in rows):
        border = "green"
    else:
        border = "yellow"
    return Panel(grid, title="6 . ENRICHMENT", border_style=border)


def _crosswalk_panel(crosswalk: dict[str, Any] | None) -> Panel:
    """Render section 9 (CROSSWALK): the ECS document and CIM field set."""
    if not crosswalk:
        return Panel(
            "[dim]no crosswalk (no OCSF record)[/]", title="9 . CROSSWALK", border_style="cyan"
        )
    grid = Table.grid(padding=(0, 2))
    grid.add_column()
    grid.add_row("[bold]ECS[/]")
    grid.add_row(_json_block(crosswalk["ecs"]))
    grid.add_row("[bold]CIM[/]")
    grid.add_row(_json_block(crosswalk["cim"]))
    return Panel(grid, title="9 . CROSSWALK", border_style="cyan")


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
    console.print(_enrichment_panel(report["enrichment"]))
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
    """Trace raw log line(s) through detect, parse, match, normalize, enrich, validate."""
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
