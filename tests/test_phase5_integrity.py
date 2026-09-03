"""Phase-5 end-to-end: the signed Merkle integrity ledger and its verification.

* ingest 5000 events -> the ledger has ``ceil(5000 / batch_size)`` entries and
  ``verify_chain()`` is ok;
* corrupt one stored raw event -> ``verify events`` names *exactly* that
  ``event_uid``;
* corrupt one ledger line -> ``verify_chain`` names *exactly* that sequence;
* the lossless round-trip rate is 100% on clean data (requirement (a));
* benchmark the integrity stage's throughput cost (printed, and written to
  ``bench/integrity_overhead.txt`` for the presentation).
"""

from __future__ import annotations

import base64
import gzip
import json
import math
import time
from pathlib import Path

import pytest

from ulpf.cli.verify import run_verify_chain, run_verify_events, run_verify_roundtrip
from ulpf.config.settings import ParseSettings, Settings, StorageSettings
from ulpf.config.settings import IntegritySettings
from ulpf.integrity.hashing import make_raw_event
from ulpf.integrity.ledger import LEDGER_FILENAME, IntegrityLedger
from ulpf.integrity.signing import Signer, generate_keypair
from ulpf.integrity.stage import IntegrityStage
from ulpf.sinks.raw_store import RawStore

_REPO = Path(__file__).resolve().parent.parent


def _lines(n: int) -> list[bytes]:
    """Distinct synthetic FortiGate traffic lines (RFC 5737 addresses)."""
    return [
        (
            f'<189>date=2026-09-04 time=10:{i // 60 % 60:02d}:{i % 60:02d} '
            f'devname="FGT" logid="0000000013" type="traffic" subtype="forward" '
            f'level="warning" srcip=192.0.2.{i % 254 + 1} srcport={10000 + i} '
            f"dstip=198.51.100.{i % 254 + 1} dstport=443 proto=6 "
            f'action="{"deny" if i % 7 == 0 else "accept"}" policyid=9 '
            f"sentbyte={i} rcvdbyte={2 * i}"
        ).encode()
        for i in range(n)
    ]


def _settings(root: Path, *, batch_size: int) -> Settings:
    keys = generate_keypair(root / "keys")
    return Settings(
        storage=StorageSettings(bronze_path=root / "bronze", ledger_path=root / "ledger"),
        parse=ParseSettings(sources_dir=_REPO / "configs" / "sources"),
        integrity=IntegritySettings(
            signing_key_path=keys.private,
            public_key_path=keys.public,
            batch_size=batch_size,
            batch_timeout_seconds=0.0,
        ),
    )


async def _ingest(settings: Settings, count: int):  # noqa: ANN202
    """Write ``count`` synthetic events to bronze and seal them via the integrity stage."""
    events = [make_raw_event(line, source_id="p5", transport="udp") for line in _lines(count)]
    store = RawStore(settings)
    for event in events:
        store.write(event)
    store.flush()
    stage = IntegrityStage(settings, signer=Signer.load(str(settings.integrity.signing_key_path)))
    for event in events:
        await stage.process(event)
    await stage.flush()
    return events, stage


def _flip_one_byte_in_bronze(settings: Settings, event_uid: str) -> None:
    """Flip one byte of one stored raw event's payload (``raw_hash`` left intact)."""
    path = next(Path(settings.storage.bronze_path).rglob("events.ndjson.gz"))
    with gzip.open(path, "rb") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    for record in records:
        if record["event_uid"] == event_uid:
            raw = bytearray(base64.b64decode(record["raw_b64"]))
            raw[len(raw) // 2] ^= 0xFF
            record["raw_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    with gzip.open(path, "wb") as handle:
        for record in records:
            handle.write((json.dumps(record, separators=(",", ":")) + "\n").encode())


def _corrupt_ledger_line(settings: Settings, seq: int) -> None:
    """Rewrite one ledger line's ``batch_root`` so its ``chained_root`` will not recompute."""
    path = Path(settings.storage.ledger_path) / LEDGER_FILENAME
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[seq])
    row["batch_root"] = "ff" * 32
    lines[seq] = json.dumps(row, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------
# 1. ledger shape for 5000 events + chain verification


async def test_5000_events_seal_into_ceil_n_over_batch_entries(tmp_path: Path) -> None:
    batch_size = 500
    settings = _settings(tmp_path, batch_size=batch_size)
    _events, stage = await _ingest(settings, 5000)

    entries = stage.ledger.entries()
    assert len(entries) == math.ceil(5000 / batch_size) == 10
    assert [e.seq for e in entries] == list(range(10))
    assert sum(e.leaf_count for e in entries) == 5000

    assert stage.ledger.verify_chain() == (True, None)
    assert run_verify_chain(settings, show_progress=False).ok is True


# --------------------------------------------------------------------------
# 2-4. share one smaller sealed store (the mutating tests each get a fresh copy)


@pytest.fixture
async def sealed(tmp_path: Path):  # noqa: ANN201
    settings = _settings(tmp_path, batch_size=200)
    events, stage = await _ingest(settings, 1000)
    return settings, events, stage


async def test_verify_events_pinpoints_a_single_corrupted_raw_event(sealed) -> None:  # noqa: ANN001
    settings, events, _stage = sealed
    victim = events[613].event_uid
    _flip_one_byte_in_bronze(settings, victim)

    report = run_verify_events(settings, date=None)

    assert report.checked == 1000
    assert report.passed == 999 and report.failed == 1
    (failure,) = report.failures
    assert failure.event_uid == victim
    assert failure.hash_ok is False and failure.proof_ok is False
    assert "#L" in failure.locator


async def test_verify_chain_pinpoints_a_single_corrupted_ledger_line(sealed) -> None:  # noqa: ANN001
    settings, _events, _stage = sealed
    _corrupt_ledger_line(settings, seq=3)

    signer = Signer.load(str(settings.integrity.signing_key_path))
    assert IntegrityLedger(settings, signer).verify_chain() == (False, 3)

    report = run_verify_chain(settings, show_progress=False)
    assert report.ok is False and report.broken_at == 3 and report.broken_reason


async def test_roundtrip_rate_is_100_percent_on_clean_data(sealed) -> None:  # noqa: ANN001
    settings, _events, _stage = sealed
    report = run_verify_roundtrip(settings, date=None)

    assert report.total == 1000
    assert report.lossless == 1000
    assert report.rate_percent == 100.0
    assert report.failures == []


# --------------------------------------------------------------------------
# 5. benchmark: integrity stage throughput cost (for the presentation)


async def test_integrity_stage_throughput_overhead(tmp_path: Path, capsys) -> None:  # noqa: ANN001
    bench_n = 8_000
    events = [make_raw_event(line, source_id="bench", transport="udp") for line in _lines(bench_n)]
    run_id = [0]

    async def _run(*, integrity_on: bool) -> float:
        run_id[0] += 1
        settings = _settings(tmp_path / f"run{run_id[0]}", batch_size=1000)
        store = RawStore(settings)
        signer = Signer.load(str(settings.integrity.signing_key_path)) if integrity_on else None
        stage = IntegrityStage(settings, signer=signer)  # disabled when signer is None
        start = time.perf_counter()
        for event in events:
            store.write(event)  # the always-present ingest cost (bronze evidence)
            await stage.process(event)
        store.flush()
        await stage.flush()
        return time.perf_counter() - start

    await _run(integrity_on=False)  # warm up (imports, gzip, sqlite)
    t_off = min([await _run(integrity_on=False), await _run(integrity_on=False)])
    t_on = min([await _run(integrity_on=True), await _run(integrity_on=True)])

    eps_off, eps_on = bench_n / t_off, bench_n / t_on
    overhead_pct = (t_on - t_off) / t_off * 100.0
    per_event_us = (t_on - t_off) / bench_n * 1_000_000

    summary = (
        "INTEGRITY STAGE THROUGHPUT OVERHEAD\n"
        f"  events per run       : {bench_n}\n"
        f"  batch size           : 1000  ({bench_n // 1000} signed batches / run)\n"
        f"  ingest, ledger OFF   : {t_off * 1000:8.1f} ms   ({eps_off:>10,.0f} events/s)\n"
        f"  ingest, ledger ON    : {t_on * 1000:8.1f} ms   ({eps_on:>10,.0f} events/s)\n"
        f"  added per event      : {per_event_us:8.2f} us\n"
        f"  throughput overhead  : {overhead_pct:8.1f} %\n"
    )
    with capsys.disabled():
        print("\n" + summary)
    (_REPO / "bench").mkdir(exist_ok=True)
    (_REPO / "bench" / "integrity_overhead.txt").write_text(summary, encoding="utf-8")

    assert eps_on > 5_000  # far above the "hundreds of EPS" a per-event ledger would allow
    assert overhead_pct < 300.0  # soft ceiling; CI timing is noisy
