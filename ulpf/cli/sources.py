"""``ulpf sources verify`` — check every source definition against a sample line.

For each YAML in the sources directory it loads the matching sample from the
fixtures directory and asserts the definition:

* matches its own sample exactly (not "no match", not a different definition),
* produces an OCSF record carrying a ``class_uid``,
* passes OCSF validation,
* scores normalization completeness above :data:`_MIN_COMPLETENESS`,
* stamps ``metadata.uid`` and ``metadata.log_hash`` (requirement d),
* parks its vendor-specific surplus fields in ``unmapped`` (requirement a).

Run it after adding a source; it doubles as a normalization demo artefact.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from ulpf.cli.inspect import _coordinator_fields, _definition_fields
from ulpf.config.settings import get_settings
from ulpf.core.errors import UlpfError
from ulpf.core.models import RawEvent
from ulpf.integrity.hashing import make_raw_event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import SourceDefinition, load_source_definition

_REPO_ROOT = Path(__file__).resolve().parents[2]
_MIN_COMPLETENESS = 0.6

# Each source YAML is verified against one representative fixture line. Adding a
# source without adding its entry here (and the file it names) fails the
# self-match suite — a source can never land without a sample.
SAMPLE_FIXTURES: dict[str, str] = {
    "aws_vpc_flow": "aws_vpc_flow_accept.log",
    "cisco_asa": "cisco_asa_302013.log",
    "fortigate_traffic": "fortigate_traffic_accept.log",
    "iptables": "iptables_drop.log",
    "panos_traffic_v10": "panos_traffic_v10.log",
    "panos_traffic_v11": "panos_traffic_v11.log",
    "suricata_eve_alert": "suricata_eve_alert.jsonl",
    "suricata_eve_flow": "suricata_eve_flow.jsonl",
    "zeek_conn": "zeek_conn.jsonl",
    "zeek_dns": "zeek_dns.jsonl",
    "zeek_http": "zeek_http.jsonl",
}


@dataclass
class SourceCheck:
    """Outcome of verifying one source definition against its sample line."""

    name: str
    fixture: str
    matched_name: str | None
    class_uid: int | None
    valid: bool
    completeness: float
    unmapped_count: int
    has_uid: bool
    has_hash: bool
    problems: list[str] = field(default_factory=list)

    @property
    def matched(self) -> bool:
        """Whether the sample matched *this exact* source definition."""
        return self.matched_name == self.name

    @property
    def ok(self) -> bool:
        """Whether every check passed."""
        return not self.problems


# --------------------------------------------------------------------------
# the checks


def check_source(definition: SourceDefinition, registry: SourceRegistry, line: str) -> SourceCheck:
    """Run match -> parse -> normalize -> validate for one sample ``line``."""
    event = make_raw_event(line.encode("utf-8"), source_id="verify", transport="file")
    sniff_fields, _ = _coordinator_fields(event)
    hit = registry.match_text(line, sniff_fields)

    fields, parse_err = _definition_fields(event, definition)
    if parse_err is not None:
        ocsf, norm_err = None, parse_err
    else:
        ocsf, norm_err = _to_ocsf(definition, fields, event)
    result = OcsfValidator(record_metrics=False).validate(ocsf) if ocsf is not None else None

    metadata = ocsf.get("metadata", {}) if isinstance(ocsf, dict) else {}
    unmapped = ocsf.get("unmapped", {}) if isinstance(ocsf, dict) else {}
    class_uid = ocsf.get("class_uid") if isinstance(ocsf, dict) else None
    check = SourceCheck(
        name=definition.name,
        fixture="",
        matched_name=hit.name if hit is not None else None,
        class_uid=class_uid if isinstance(class_uid, int) else None,
        valid=bool(result and result.valid),
        completeness=result.completeness if result is not None else 0.0,
        unmapped_count=len(unmapped) if isinstance(unmapped, dict) else 0,
        has_uid=bool(metadata.get("uid")),
        has_hash=bool(metadata.get("log_hash")),
    )
    check.problems = _problems(check, hit, definition, norm_err)
    return check


def _to_ocsf(
    definition: SourceDefinition, fields: dict[str, Any], event: RawEvent
) -> tuple[dict[str, Any] | None, UlpfError | None]:
    """Map + finalize; return ``(record, None)`` or ``(None, error)``."""
    try:
        mapped = Mapper().to_ocsf(
            definition, fields, event_uid=event.event_uid, raw_hash=event.raw_hash
        )
        return finalize(mapped), None
    except UlpfError as exc:
        return None, exc


def _problems(
    check: SourceCheck,
    hit: SourceDefinition | None,
    definition: SourceDefinition,
    error: UlpfError | None,
) -> list[str]:
    """Collect every failed expectation for one source (empty list == all good)."""
    out: list[str] = []
    if error is not None:
        out.append(f"parse/normalize error: {error}")
    if hit is None:
        out.append("no source matched this sample")
    elif hit.name != definition.name:
        out.append(f"sample matched a different source: {hit.name}")
    if check.class_uid is None:
        out.append("OCSF record has no class_uid")
    if not check.valid:
        out.append("OCSF validation failed")
    if check.completeness <= _MIN_COMPLETENESS:
        out.append(f"completeness {check.completeness:.0%} <= {_MIN_COMPLETENESS:.0%}")
    if not check.has_uid:
        out.append("metadata.uid missing")
    if not check.has_hash:
        out.append("metadata.log_hash missing")
    if check.unmapped_count == 0:
        out.append("unmapped is empty (vendor surplus fields not preserved)")
    return out


def verify_all(sources_dir: Path, fixtures_dir: Path) -> tuple[list[SourceCheck], list[str]]:
    """Check every ``*.yaml`` in ``sources_dir``; return (checks, sources-with-no-fixture)."""
    registry = SourceRegistry()
    registry.load_all(sources_dir)
    checks: list[SourceCheck] = []
    missing: list[str] = []
    for path in sorted(sources_dir.glob("*.yaml")):
        definition = load_source_definition(yaml.safe_load(path.read_text("utf-8")))
        fixture_name = SAMPLE_FIXTURES.get(definition.name)
        fixture_path = fixtures_dir / fixture_name if fixture_name else None
        if fixture_path is None or not fixture_path.is_file():
            missing.append(definition.name)
            continue
        check = check_source(definition, registry, _first_line(fixture_path))
        check.fixture = fixture_name or ""
        checks.append(check)
    return checks, missing


def _first_line(path: Path) -> str:
    """First non-blank line of ``path``."""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            return line
    raise ValueError(f"fixture {path} has no non-blank line")


# --------------------------------------------------------------------------
# the CLI


sources_app = typer.Typer(help="Inspect and verify source definitions.", no_args_is_help=True)


def _resolve_dir(explicit: Path | None, configured: Path, repo_relative: str) -> Path:
    """Resolve a directory: the flag, else the configured path, else repo-relative."""
    if explicit is not None:
        return explicit
    if configured.is_absolute():
        return configured
    for base in (Path.cwd(), _REPO_ROOT):
        if (base / configured).is_dir():
            return base / configured
    return _REPO_ROOT / repo_relative


@sources_app.command("verify")
def verify(
    sources: Path | None = typer.Option(None, "--sources", help="Source-definition directory."),
    fixtures: Path | None = typer.Option(None, "--fixtures", help="Sample-line directory."),
) -> None:
    """Verify every source definition against a representative sample line."""
    sources_dir = _resolve_dir(sources, get_settings().parse.sources_dir, "configs/sources")
    fixtures_dir = _resolve_dir(fixtures, Path("tests/fixtures"), "tests/fixtures")
    checks, missing = verify_all(sources_dir, fixtures_dir)

    console = Console()
    _render_table(console, checks)
    for name in missing:
        console.print(f"[red]MISSING FIXTURE[/] — source {name!r} has no sample line")

    failed = [c for c in checks if not c.ok]
    for check in failed:
        console.print(f"[red]{check.name}[/]: " + "; ".join(check.problems))
    if failed or missing:
        console.print(f"\n[red]{len(failed) + len(missing)} source(s) failed verification[/]")
        raise typer.Exit(code=1)
    console.print(f"\n[green]all {len(checks)} sources verified[/]")


def _render_table(console: Console, checks: list[SourceCheck]) -> None:
    """Print the summary table: source, matched, class_uid, valid, completeness, unmapped."""
    table = Table(title="ulpf sources verify", header_style="bold", title_style="bold")
    table.add_column("source", no_wrap=True)
    table.add_column("matched", no_wrap=True)
    table.add_column("class_uid", justify="right")
    table.add_column("valid")
    table.add_column("compl %", justify="right")
    table.add_column("unmapped", justify="right")
    for check in checks:
        table.add_row(
            f"[red]{check.name}[/]" if not check.ok else check.name,
            _matched_cell(check),
            str(check.class_uid) if check.class_uid is not None else "[red]-[/]",
            "[green]yes[/]" if check.valid else "[red]no[/]",
            _completeness_cell(check.completeness),
            str(check.unmapped_count) if check.unmapped_count else "[yellow]0[/]",
        )
    console.print(table)


def _matched_cell(check: SourceCheck) -> str:
    """``yes`` when the sample matched this exact source; else the wrong name / ``NO``."""
    if check.matched_name == check.name:
        return "[green]yes[/]"
    if check.matched_name is not None:
        return f"[red]{check.matched_name}[/]"  # matched the wrong definition
    return "[red]NO[/]"


def _completeness_cell(value: float) -> str:
    """Completeness as a whole-number percent, red below the threshold."""
    pct = f"{value * 100:.0f}"
    return pct if value > _MIN_COMPLETENESS else f"[red]{pct}[/]"
