"""IntegrityStage is wired into the Runtime right after RawStoreStage and seals
the raw evidence on graceful shutdown."""

from __future__ import annotations

import asyncio
from pathlib import Path

from ulpf.config.settings import (
    IngestSettings,
    IntegritySettings,
    ParseSettings,
    PipelineSettings,
    Settings,
    StorageSettings,
)
from ulpf.core.runtime import Runtime
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import LEDGER_FILENAME, IntegrityLedger
from ulpf.integrity.signing import Signer, generate_keypair
from ulpf.sinks.raw_store import RawStore


def _settings(tmp_path: Path, key_path: Path) -> Settings:
    return Settings(
        storage=StorageSettings(
            bronze_path=tmp_path / "bronze",
            silver_path=tmp_path / "silver",
            dlq_path=tmp_path / "dlq",
            ledger_path=tmp_path / "ledger",
            state_path=tmp_path / "state",
        ),
        ingest=IngestSettings(syslog_udp_port=0, syslog_tcp_port=0, http_port=0),
        parse=ParseSettings(sources_dir=tmp_path / "sources"),
        pipeline=PipelineSettings(worker_count=1),
        # only shutdown (not size or timeout) will seal, so the assertion is exact
        integrity=IntegritySettings(
            signing_key_path=key_path, batch_size=10_000, batch_timeout_seconds=0.0
        ),
    )


async def test_runtime_seals_the_raw_evidence_batch_on_shutdown(tmp_path: Path) -> None:
    key_path = generate_keypair(tmp_path / "keys").private
    settings = _settings(tmp_path, key_path)
    runtime = Runtime(settings)
    await runtime.start()
    try:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, remote_addr=("127.0.0.1", runtime.udp_port)
        )
        for i in range(3):
            transport.sendto(f"<13>evt {i}".encode())
            await asyncio.sleep(0)  # let the listener drain each datagram
        transport.close()
        await asyncio.sleep(0.4)
    finally:
        await runtime.stop()  # drains the queue, then flushes -> seals the partial batch

    # whatever raw evidence arrived is in bronze...
    events = list(RawStore(settings).iter_all())
    assert len(events) >= 1

    # ...and one signed, chained ledger entry now covers exactly those hashes
    ledger_file = tmp_path / "ledger" / LEDGER_FILENAME
    assert ledger_file.is_file()
    ledger = IntegrityLedger(settings, Signer.load(key_path))
    assert ledger.verify_chain() == (True, None)
    entry = ledger.entries()[0]
    assert entry.leaf_count == len(events)  # the whole partial batch was sealed

    # the per-event index maps every bronze event into that batch
    index = IntegrityIndex(tmp_path / "ledger" / "event_index.sqlite")
    for event in events:
        located = index.lookup(event.event_uid)
        assert located is not None and located[0] == 0
    assert sorted(index.lookup(e.event_uid)[1] for e in events) == list(range(len(events)))
    index.close()


async def test_runtime_without_a_signing_key_runs_with_integrity_off(tmp_path: Path) -> None:
    settings = _settings(tmp_path, tmp_path / "keys" / "absent.pem")
    runtime = Runtime(settings)
    await runtime.start()
    await runtime.stop()
    assert not (tmp_path / "ledger" / LEDGER_FILENAME).exists()
