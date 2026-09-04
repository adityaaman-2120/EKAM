"""``ulpf verify`` — prove the integrity and lossless round-trip of the evidence.

This is the command demonstrated on film, so every path prints a clean
green/red table:

* ``ulpf verify chain``     — recompute every ledger entry's chained root and
  check its Ed25519 signature; a break names the exact sequence number.
* ``ulpf verify events``    — for every raw event in bronze: re-read, re-hash,
  compare to the recorded ``raw_hash``, and verify its Merkle inclusion proof
  against the signed ledger. Reports total / passed / FAILED (with each failing
  ``event_uid`` and file locator).
* ``ulpf verify event <uid>`` — full detail for one event, including the Merkle
  authentication path.
* ``ulpf verify roundtrip`` — re-derive every stored raw event and report three
  **independent** properties, never conflated:

  - ``byte_lossless_rate`` — the stored raw re-reads and re-hashes to the
    recorded SHA-256. **This alone is requirement (a)** (no information loss),
    and it is the panel headline.
  - ``reparse_stable_rate`` — parsing the raw twice yields the identical field
    dict (parser determinism).
  - ``renormalize_stable_rate`` — normalizing twice yields the identical OCSF
    record, computed **only over events that normalized successfully the first
    time**. Events whose mapping failed are excluded from that denominator and
    counted as ``dead_letter_count`` — a mapping failure is a parser-coverage
    gap, not evidence loss, so it must not drag down requirement (a).

Every command takes ``--json`` for machine-readable output and exits non-zero on
any failure.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import track
from rich.table import Table

from ulpf.config.settings import Settings, get_settings
from ulpf.core.errors import MappingError, ParseError
from ulpf.core.models import ParsedEvent, RawEvent, sha256_hex
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import LEDGER_FILENAME, IntegrityLedger
from ulpf.integrity.proofs import EventProof, ProofBuilder
from ulpf.integrity.signing import Signer, Verifier
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.raw_store import RawStore

verify_app = typer.Typer(
    help="Verify ledger integrity and lossless round-trip.", no_args_is_help=True
)

_OK = "[bold green]PASS[/]"
_BAD = "[bold red]FAIL[/]"
_INDEX_FILENAME = "event_index.sqlite"


def _load_settings() -> Settings:
    """Indirection so tests can point the commands at a temp configuration."""
    return get_settings()


# --------------------------------------------------------------------------
# artefact loading


def _load_verifier(settings: Settings) -> Verifier | None:
    integrity = settings.integrity
    if integrity.public_key_path and Path(integrity.public_key_path).is_file():
        return Verifier.load(integrity.public_key_path)
    if integrity.signing_key_path and Path(integrity.signing_key_path).is_file():
        return Signer.load(integrity.signing_key_path).verifier()
    return None


def _load_ledger(settings: Settings) -> IntegrityLedger | None:
    if not (Path(settings.storage.ledger_path) / LEDGER_FILENAME).is_file():
        return None
    return IntegrityLedger(settings, verifier=_load_verifier(settings))


def _load_index(settings: Settings) -> IntegrityIndex | None:
    path = Path(settings.storage.ledger_path) / _INDEX_FILENAME
    return IntegrityIndex(path) if path.is_file() else None


def _load_registry(settings: Settings) -> SourceRegistry:
    registry = SourceRegistry()
    registry.load_all(settings.parse.sources_dir)
    return registry


# ======================================================================
# verify chain
# ======================================================================


@dataclass
class ChainReport:
    ledger_present: bool
    entries_total: int
    checked: int
    ok: bool
    broken_at: int | None
    broken_reason: str | None
    head_hex: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_verify_chain(settings: Settings, *, show_progress: bool) -> ChainReport:
    """Walk the ledger, checking every link and signature."""
    ledger = _load_ledger(settings)
    if ledger is None:
        return ChainReport(
            ledger_present=False,
            entries_total=0,
            checked=0,
            ok=True,
            broken_at=None,
            broken_reason="no ledger file found",
            head_hex="",
        )

    total = ledger.entry_count_on_disk()
    stream = ledger.iter_checked()
    if show_progress and total:
        stream = track(stream, total=total, description="verifying chain")

    checked = 0
    broken_at: int | None = None
    reason: str | None = None
    for index, _entry, entry_reason in stream:
        checked += 1
        if entry_reason is not None:
            broken_at, reason = index, entry_reason
            break

    return ChainReport(
        ledger_present=True,
        entries_total=total,
        checked=checked,
        ok=broken_at is None,
        broken_at=broken_at,
        broken_reason=reason,
        head_hex=ledger.head.hex(),
    )


def _render_chain(console: Console, report: ChainReport) -> None:
    if not report.ledger_present:
        console.print(
            Panel(
                "[yellow]No integrity ledger found.[/] Nothing sealed yet, "
                "or `integrity.signing_key_path` is not configured.",
                title="verify chain",
                border_style="yellow",
            )
        )
        return
    if report.entries_total == 0:
        console.print(
            Panel(
                "[yellow]Ledger is empty[/] — no batches have been sealed yet.",
                title="verify chain",
                border_style="yellow",
            )
        )
        return
    if report.ok:
        console.print(
            Panel(
                f"[bold green]LEDGER INTACT[/]\n"
                f"{report.entries_total} entries checked · every chained root recomputes · "
                f"every signature valid\nhead = [cyan]{report.head_hex[:16]}…[/]",
                title="verify chain",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]CHAIN BROKEN AT SEQ {report.broken_at}[/]\n"
                f"{report.broken_reason}\n"
                f"(verified {report.checked - 1} entries before the break)",
                title="verify chain",
                border_style="red",
            )
        )


@verify_app.command("chain")
def verify_chain(
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Verify every ledger entry's chained root and signature."""
    report = run_verify_chain(_load_settings(), show_progress=not json_out)
    if json_out:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _render_chain(Console(), report)
    raise typer.Exit(code=0 if report.ok else 1)


# ======================================================================
# verify events
# ======================================================================


@dataclass
class EventFailure:
    event_uid: str
    locator: str
    hash_ok: bool
    proof_ok: bool
    signature_ok: bool
    reason: str


@dataclass
class EventsReport:
    checked: int
    passed: int
    failed: int
    ledger_present: bool
    failures: list[EventFailure] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "passed": self.passed,
            "failed": self.failed,
            "ledger_present": self.ledger_present,
            "failures": [asdict(failure) for failure in self.failures],
        }


def run_verify_events(settings: Settings, date: str | None) -> EventsReport:
    """Re-hash and Merkle-verify every raw event in the bronze store."""
    store = RawStore(settings)
    ledger = _load_ledger(settings)
    located = list(store.iter_located(date))
    event_cache = {event.event_uid: event for event, _ in located}
    builder = ProofBuilder(store, _load_index(settings), ledger, event_cache=event_cache)

    checked = passed = 0
    failures: list[EventFailure] = []
    for event, locator in located:
        checked += 1
        proof = builder.for_event(event.event_uid)
        if _event_passed(proof, ledger_present=ledger is not None):
            passed += 1
        else:
            failures.append(_failure(proof, locator))

    return EventsReport(checked, passed, len(failures), ledger is not None, failures)


def _event_passed(proof: EventProof, *, ledger_present: bool) -> bool:
    if not proof.hash_ok:
        return False
    if not ledger_present:
        return True  # re-hash matched; no ledger to prove inclusion against
    return proof.found and proof.proof_ok and proof.signature_ok


def _failure(proof: EventProof, locator: str) -> EventFailure:
    if not proof.hash_ok:
        reason = "raw bytes do not match the recorded raw_hash (tampered)"
    elif not proof.found:
        reason = proof.reason or "not indexed by any sealed batch"
    elif not proof.proof_ok:
        reason = "Merkle inclusion proof does not verify against the batch root"
    elif not proof.signature_ok:
        reason = "the batch's ledger entry signature is invalid"
    else:
        reason = proof.reason or "unknown"
    return EventFailure(
        proof.event_uid, locator, proof.hash_ok, proof.proof_ok, proof.signature_ok, reason
    )


def _render_events(console: Console, report: EventsReport) -> None:
    if not report.ledger_present:
        console.print(
            "[yellow]No ledger — checking raw-hash integrity only (no Merkle inclusion proofs).[/]"
        )
    if report.failures:
        table = Table(title="verify events — FAILURES", border_style="red", show_lines=True)
        table.add_column("event_uid", style="cyan", no_wrap=True)
        table.add_column("locator")
        table.add_column("hash")
        table.add_column("proof")
        table.add_column("sig")
        table.add_column("reason", style="red")
        for failure in report.failures:
            table.add_row(
                failure.event_uid,
                failure.locator,
                _OK if failure.hash_ok else _BAD,
                _OK if failure.proof_ok else _BAD,
                _OK if failure.signature_ok else _BAD,
                failure.reason,
            )
        console.print(table)

    style = "green" if report.failed == 0 else "red"
    verdict = "ALL EVENTS VERIFIED" if report.failed == 0 else f"{report.failed} EVENT(S) FAILED"
    console.print(
        Panel(
            f"[bold {style}]{verdict}[/]\n"
            f"checked [bold]{report.checked}[/] · passed [green]{report.passed}[/] · "
            f"failed [red]{report.failed}[/]",
            title="verify events",
            border_style=style,
        )
    )


@verify_app.command("events")
def verify_events(
    date: str | None = typer.Option(
        None, "--date", help="Restrict to one ingest date (YYYY-MM-DD)."
    ),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Re-hash and Merkle-verify every raw event in the bronze store."""
    report = run_verify_events(_load_settings(), date)
    if json_out:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _render_events(Console(), report)
    raise typer.Exit(code=0 if report.failed == 0 else 1)


# ======================================================================
# verify event <uid>
# ======================================================================


def _event_detail_dict(proof: EventProof) -> dict[str, Any]:
    return {
        "event_uid": proof.event_uid,
        "found": proof.found,
        "ok": proof.ok,
        "hash_ok": proof.hash_ok,
        "proof_ok": proof.proof_ok,
        "signature_ok": proof.signature_ok,
        "ledger_seq": proof.ledger_seq,
        "leaf_index": proof.leaf_index,
        "recorded_hash": proof.recorded_hash.hex() if proof.recorded_hash else None,
        "recomputed_hash": proof.recomputed_hash.hex() if proof.recomputed_hash else None,
        "batch_root": proof.batch_root.hex() if proof.batch_root else None,
        "chained_root": proof.chained_root.hex() if proof.chained_root else None,
        "merkle_path": [{"sibling": sibling.hex(), "side": side} for sibling, side in proof.proof],
        "reason": proof.reason,
    }


def _render_event(console: Console, proof: EventProof) -> None:
    facts = Table(box=None, show_header=False)
    facts.add_column(style="bold")
    facts.add_column()
    facts.add_row("event_uid", f"[cyan]{proof.event_uid}[/]")
    facts.add_row("recorded raw_hash", (proof.recorded_hash or b"").hex() or "—")
    facts.add_row("recomputed hash", (proof.recomputed_hash or b"").hex() or "—")
    facts.add_row("bytes match", _OK if proof.hash_ok else _BAD)
    facts.add_row("ledger seq", str(proof.ledger_seq) if proof.ledger_seq is not None else "—")
    facts.add_row("leaf index", str(proof.leaf_index) if proof.leaf_index is not None else "—")
    facts.add_row("batch root", (proof.batch_root or b"").hex() or "—")
    facts.add_row("proof verifies", _OK if proof.proof_ok else _BAD)
    facts.add_row("batch signature", _OK if proof.signature_ok else _BAD)
    console.print(facts)

    if proof.proof:
        path = Table(title="Merkle authentication path", border_style="cyan")
        path.add_column("#", justify="right")
        path.add_column("sibling hash", style="cyan")
        path.add_column("side")
        for step, (sibling, side) in enumerate(proof.proof):
            path.add_row(str(step), sibling.hex(), side)
        console.print(path)

    style = "green" if proof.ok else "red"
    verdict = "EVENT VERIFIED" if proof.ok else "EVENT VERIFICATION FAILED"
    detail = "" if proof.ok else f"\n{proof.reason or 'see the checks above'}"
    console.print(
        Panel(f"[bold {style}]{verdict}[/]{detail}", title="verify event", border_style=style)
    )


@verify_app.command("event")
def verify_event(
    event_uid: str = typer.Argument(..., help="The event UID to verify."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Full integrity detail for one event, including its Merkle proof path."""
    settings = _load_settings()
    builder = ProofBuilder(RawStore(settings), _load_index(settings), _load_ledger(settings))
    proof = builder.for_event(event_uid)
    if json_out:
        typer.echo(json.dumps(_event_detail_dict(proof), indent=2))
    else:
        _render_event(Console(), proof)
    raise typer.Exit(code=0 if proof.ok else 1)


# ======================================================================
# verify roundtrip  — three independent properties, never conflated
# ======================================================================


@dataclass
class RoundtripFailure:
    event_uid: str
    locator: str
    category: str  # "byte" | "reparse" | "renormalize"
    reason: str


@dataclass
class _Outcome:
    """Per-event result of the round-trip re-derivation."""

    byte_lossless: bool
    reparse_stable: bool
    normalized_originally: bool  # a source matched AND the 1st normalize() succeeded
    renormalize_stable: bool  # meaningful only when normalized_originally
    dead_lettered: bool  # a source matched but normalize() raised MappingError
    no_source_match: bool
    note: str  # short reason for the (first) non-green property


@dataclass
class RoundtripReport:
    total: int
    byte_lossless: int
    reparse_stable: int
    normalized_originally: int  # denominator for renormalize_stable_rate
    renormalize_stable: int
    dead_letter_count: int
    no_source_match_count: int
    failures: list[RoundtripFailure] = field(default_factory=list)

    def _rate(self, numerator: int, denominator: int) -> float:
        return 100.0 if denominator == 0 else numerator / denominator * 100.0

    @property
    def byte_lossless_rate(self) -> float:
        return self._rate(self.byte_lossless, self.total)

    @property
    def reparse_stable_rate(self) -> float:
        return self._rate(self.reparse_stable, self.total)

    @property
    def renormalize_stable_rate(self) -> float:
        return self._rate(self.renormalize_stable, self.normalized_originally)

    @property
    def requirement_a_satisfied(self) -> bool:
        """Requirement (a) is byte-level and byte-level ONLY."""
        return self.byte_lossless == self.total

    @property
    def all_green(self) -> bool:
        return (
            self.requirement_a_satisfied
            and self.reparse_stable == self.total
            and self.renormalize_stable == self.normalized_originally
            and self.dead_letter_count == 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "requirement_a_satisfied": self.requirement_a_satisfied,
            "byte_lossless": self.byte_lossless,
            "byte_lossless_rate": round(self.byte_lossless_rate, 4),
            "reparse_stable": self.reparse_stable,
            "reparse_stable_rate": round(self.reparse_stable_rate, 4),
            "normalized_originally": self.normalized_originally,
            "renormalize_stable": self.renormalize_stable,
            "renormalize_stable_rate": round(self.renormalize_stable_rate, 4),
            "dead_letter_count": self.dead_letter_count,
            "no_source_match_count": self.no_source_match_count,
            "failures": [asdict(failure) for failure in self.failures],
        }


def _parse_signature(parsed: ParsedEvent) -> str:
    return json.dumps(
        {"format": parsed.format, "fields": parsed.fields, "envelope": parsed.envelope},
        sort_keys=True,
        default=str,
    )


def _normalize_signature(definition: Any, parsed: ParsedEvent) -> str:
    ocsf = finalize(
        Mapper().apply(
            definition, parsed.fields, event_uid=parsed.event_uid, raw_hash=parsed.raw_hash
        )
    )
    return json.dumps(ocsf, sort_keys=True, default=str)


def _check_reparse(
    event: RawEvent, coordinator: ParseCoordinator
) -> tuple[ParsedEvent | None, bool, str]:
    """``(parsed, stable, note)`` — parse the raw twice and compare."""
    try:
        first = coordinator.parse(event)
        second = coordinator.parse(event)
    except ParseError as exc:
        return None, False, f"parse failed: {exc}"
    if first.raw != event.raw:
        return first, False, "raw bytes changed while parsing"
    if _parse_signature(first) != _parse_signature(second):
        return first, False, "parse is not deterministic"
    return first, True, ""


def _check_renormalize(definition: Any, parsed: ParsedEvent) -> tuple[bool, bool, str]:
    """``(normalized_originally, stable, note)`` — normalize twice and compare."""
    try:
        first = _normalize_signature(definition, parsed)
    except MappingError as exc:
        return False, False, f"normalization failed (dead-lettered): {exc}"
    try:
        second = _normalize_signature(definition, parsed)
    except MappingError:
        return True, False, "normalization is not deterministic (2nd pass raised)"
    if first != second:
        return True, False, "normalization is not deterministic"
    return True, True, ""


def _roundtrip_one(
    event: RawEvent, coordinator: ParseCoordinator, registry: SourceRegistry
) -> _Outcome:
    """Re-derive one event, scoring the three properties independently."""
    byte_lossless = sha256_hex(event.raw) == event.raw_hash
    note = "" if byte_lossless else "raw bytes were altered in storage"

    parsed, reparse_stable, parse_note = _check_reparse(event, coordinator)
    note = note or parse_note

    normalized_originally = renormalize_stable = dead_lettered = no_source_match = False
    if parsed is not None:
        definition = registry.match(parsed)
        if definition is None:
            no_source_match = True
        else:
            normalized_originally, renormalize_stable, norm_note = _check_renormalize(
                definition, parsed
            )
            dead_lettered = not normalized_originally
            note = note or norm_note

    return _Outcome(
        byte_lossless,
        reparse_stable,
        normalized_originally,
        renormalize_stable,
        dead_lettered,
        no_source_match,
        note,
    )


def run_verify_roundtrip(settings: Settings, date: str | None) -> RoundtripReport:
    """Re-derive every stored raw event; score byte / reparse / renormalize separately."""
    store = RawStore(settings)
    coordinator = ParseCoordinator()
    registry = _load_registry(settings)

    report = RoundtripReport(0, 0, 0, 0, 0, 0, 0)
    for event, locator in store.iter_located(date):
        outcome = _roundtrip_one(event, coordinator, registry)
        report.total += 1
        report.byte_lossless += outcome.byte_lossless
        report.reparse_stable += outcome.reparse_stable
        report.normalized_originally += outcome.normalized_originally
        report.renormalize_stable += outcome.renormalize_stable and outcome.normalized_originally
        report.dead_letter_count += outcome.dead_lettered
        report.no_source_match_count += outcome.no_source_match
        _record_failure(report, event.event_uid, locator, outcome)
    return report


def _record_failure(
    report: RoundtripReport, event_uid: str, locator: str, outcome: _Outcome
) -> None:
    """Add a categorised failure row for a byte / reparse / renormalize break (not dead-letters)."""
    if not outcome.byte_lossless:
        category = "byte"
    elif not outcome.reparse_stable:
        category = "reparse"
    elif outcome.normalized_originally and not outcome.renormalize_stable:
        category = "renormalize"
    else:
        return
    report.failures.append(RoundtripFailure(event_uid, locator, category, outcome.note))


def _render_roundtrip(console: Console, report: RoundtripReport) -> None:
    if report.failures:
        table = Table(title="round-trip FAILURES", border_style="red", show_lines=True)
        table.add_column("event_uid", style="cyan", no_wrap=True)
        table.add_column("locator")
        table.add_column("category")
        table.add_column("reason", style="red")
        for failure in report.failures[:50]:
            table.add_row(failure.event_uid, failure.locator, failure.category, failure.reason)
        console.print(table)

    req_a = report.requirement_a_satisfied
    head = (
        "[bold green]REQUIREMENT (a): SATISFIED[/] — complete raw data preserved"
        if req_a
        else "[bold red]REQUIREMENT (a): NOT SATISFIED[/] — stored raw bytes do not re-hash"
    )
    renorm_denom = report.normalized_originally
    lines = [
        head,
        "",
        f"  byte-lossless      [bold]{report.byte_lossless_rate:6.2f}%[/]  "
        f"({report.byte_lossless}/{report.total})   <- requirement (a)",
        f"  reparse-stable     [bold]{report.reparse_stable_rate:6.2f}%[/]  "
        f"({report.reparse_stable}/{report.total})   parser determinism",
        f"  renormalize-stable [bold]{report.renormalize_stable_rate:6.2f}%[/]  "
        f"({report.renormalize_stable}/{renorm_denom})   over events that normalized",
    ]
    if report.dead_letter_count:
        lines.append(
            f"  dead-lettered      [yellow]{report.dead_letter_count}[/]        "
            "source matched but mapping failed — parser-coverage gap, NOT evidence loss"
        )
    if report.no_source_match_count:
        lines.append(
            f"  no source match   [dim]{report.no_source_match_count}[/]        "
            "excluded from the renormalize denominator"
        )
    console.print(
        Panel(
            "\n".join(lines),
            title="verify roundtrip",
            border_style="green" if req_a else "red",
        )
    )


@verify_app.command("roundtrip")
def verify_roundtrip(
    date: str | None = typer.Option(
        None, "--date", help="Restrict to one ingest date (YYYY-MM-DD)."
    ),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Re-derive every stored raw event; report byte / reparse / renormalize rates."""
    report = run_verify_roundtrip(_load_settings(), date)
    if json_out:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _render_roundtrip(Console(), report)
    raise typer.Exit(code=0 if report.all_green else 1)
