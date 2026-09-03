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
* ``ulpf verify roundtrip`` — re-run parse + normalize on every stored raw event
  and assert the derivation is byte-identical, with the raw bytes carried
  through untouched. Reports the **lossless round-trip rate** — the proof of
  requirement (a).

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

verify_app = typer.Typer(help="Verify ledger integrity and lossless round-trip.", no_args_is_help=True)

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
            ledger_present=False, entries_total=0, checked=0, ok=True,
            broken_at=None, broken_reason="no ledger file found", head_hex="",
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
        console.print(Panel("[yellow]No integrity ledger found.[/] Nothing sealed yet, "
                            "or `integrity.signing_key_path` is not configured.",
                            title="verify chain", border_style="yellow"))
        return
    if report.entries_total == 0:
        console.print(Panel("[yellow]Ledger is empty[/] — no batches have been sealed yet.",
                            title="verify chain", border_style="yellow"))
        return
    if report.ok:
        console.print(Panel(
            f"[bold green]LEDGER INTACT[/]\n"
            f"{report.entries_total} entries checked · every chained root recomputes · "
            f"every signature valid\nhead = [cyan]{report.head_hex[:16]}…[/]",
            title="verify chain", border_style="green"))
    else:
        console.print(Panel(
            f"[bold red]CHAIN BROKEN AT SEQ {report.broken_at}[/]\n"
            f"{report.broken_reason}\n"
            f"(verified {report.checked - 1} entries before the break)",
            title="verify chain", border_style="red"))


@verify_app.command("chain")
def verify_chain(json_out: bool = typer.Option(False, "--json", help="Machine-readable output.")) -> None:
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
        console.print("[yellow]No ledger — checking raw-hash integrity only "
                      "(no Merkle inclusion proofs).[/]")
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
                failure.event_uid, failure.locator,
                _OK if failure.hash_ok else _BAD,
                _OK if failure.proof_ok else _BAD,
                _OK if failure.signature_ok else _BAD,
                failure.reason,
            )
        console.print(table)

    style = "green" if report.failed == 0 else "red"
    verdict = "ALL EVENTS VERIFIED" if report.failed == 0 else f"{report.failed} EVENT(S) FAILED"
    console.print(Panel(
        f"[bold {style}]{verdict}[/]\n"
        f"checked [bold]{report.checked}[/] · passed [green]{report.passed}[/] · "
        f"failed [red]{report.failed}[/]",
        title="verify events", border_style=style))


@verify_app.command("events")
def verify_events(
    date: str | None = typer.Option(None, "--date", help="Restrict to one ingest date (YYYY-MM-DD)."),
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
        "merkle_path": [
            {"sibling": sibling.hex(), "side": side} for sibling, side in proof.proof
        ],
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
    console.print(Panel(f"[bold {style}]{verdict}[/]{detail}",
                        title="verify event", border_style=style))


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
# verify roundtrip  — the proof of requirement (a)
# ======================================================================


@dataclass
class RoundtripFailure:
    event_uid: str
    locator: str
    reason: str


@dataclass
class RoundtripReport:
    total: int
    lossless: int
    rate_percent: float
    failures: list[RoundtripFailure] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "lossless": self.lossless,
            "rate_percent": round(self.rate_percent, 4),
            "failures": [asdict(failure) for failure in self.failures],
        }


def _parse_signature(parsed: ParsedEvent) -> str:
    return json.dumps(
        {"format": parsed.format, "fields": parsed.fields, "envelope": parsed.envelope},
        sort_keys=True, default=str,
    )


def _normalize_signature(definition: Any, parsed: ParsedEvent) -> str:
    ocsf = finalize(
        Mapper().apply(
            definition, parsed.fields, event_uid=parsed.event_uid, raw_hash=parsed.raw_hash
        )
    )
    return json.dumps(ocsf, sort_keys=True, default=str)


def _roundtrip_one(
    event: RawEvent, coordinator: ParseCoordinator, registry: SourceRegistry
) -> str | None:
    """Return ``None`` when the event round-trips losslessly, else a failure reason."""
    if sha256_hex(event.raw) != event.raw_hash:
        return "raw bytes were altered in storage"
    try:
        first = coordinator.parse(event)
        second = coordinator.parse(event)
    except ParseError as exc:
        return f"parse failed: {exc}"
    if first.raw != event.raw:
        return "raw bytes changed while parsing"
    if _parse_signature(first) != _parse_signature(second):
        return "parse is not deterministic"

    definition = registry.match(first)
    if definition is None:
        return None  # no source matched: raw preserved + parse deterministic is enough
    try:
        if _normalize_signature(definition, first) != _normalize_signature(definition, second):
            return "normalization is not deterministic"
    except MappingError as exc:
        return f"normalization failed: {exc}"
    return None


def run_verify_roundtrip(settings: Settings, date: str | None) -> RoundtripReport:
    """Re-derive parse+normalize for every stored raw event and check it is identical."""
    store = RawStore(settings)
    coordinator = ParseCoordinator()
    registry = _load_registry(settings)

    total = lossless = 0
    failures: list[RoundtripFailure] = []
    for event, locator in store.iter_located(date):
        total += 1
        reason = _roundtrip_one(event, coordinator, registry)
        if reason is None:
            lossless += 1
        else:
            failures.append(RoundtripFailure(event.event_uid, locator, reason))

    rate = 100.0 if total == 0 else (lossless / total) * 100.0
    return RoundtripReport(total, lossless, rate, failures)


def _render_roundtrip(console: Console, report: RoundtripReport) -> None:
    if report.failures:
        table = Table(title="round-trip FAILURES", border_style="red", show_lines=True)
        table.add_column("event_uid", style="cyan", no_wrap=True)
        table.add_column("locator")
        table.add_column("reason", style="red")
        for failure in report.failures[:50]:
            table.add_row(failure.event_uid, failure.locator, failure.reason)
        console.print(table)

    perfect = report.lossless == report.total
    style = "green" if perfect else "red"
    console.print(Panel(
        f"[bold {style}]LOSSLESS ROUND-TRIP RATE: {report.rate_percent:.2f}%[/]\n"
        f"{report.lossless} / {report.total} stored raw events re-derive byte-identically "
        f"with their bytes intact\n"
        + ("[bold green]requirement (a) satisfied — complete raw data preserved, "
           "no information loss[/]" if perfect
           else "[bold red]requirement (a) NOT satisfied — see failures above[/]"),
        title="verify roundtrip", border_style=style))


@verify_app.command("roundtrip")
def verify_roundtrip(
    date: str | None = typer.Option(None, "--date", help="Restrict to one ingest date (YYYY-MM-DD)."),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output."),
) -> None:
    """Re-run parse+normalize on every stored raw event; report the lossless rate."""
    report = run_verify_roundtrip(_load_settings(), date)
    if json_out:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        _render_roundtrip(Console(), report)
    raise typer.Exit(code=0 if report.lossless == report.total else 1)
