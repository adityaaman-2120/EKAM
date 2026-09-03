"""``IntegrityStage`` — batch raw-event hashes into signed Merkle roots.

Wired **immediately after** :class:`~ulpf.core.pipeline.RawStoreStage`: integrity
must cover the *raw evidence* exactly as received, before any sniffing, envelope
stripping, parsing, or normalization can lose or alter a byte. It never modifies
the event — it accumulates ``raw_hash`` and passes the event straight through.

Each event's 32-byte ``raw_hash`` becomes a Merkle leaf. The stage seals the
current batch when **either** it reaches ``integrity.batch_size`` events **or**
``integrity.batch_timeout_seconds`` have elapsed since the batch's first event —
whichever comes first (a background poll enforces the timeout when traffic goes
quiet). On graceful shutdown the partial batch is sealed too, so no evidence is
left uncommitted.

Sealing:

1. fold the batch's leaf hashes into one Merkle root;
2. append a chained, Ed25519-signed :class:`~ulpf.integrity.ledger.LedgerEntry`;
3. write one :class:`~ulpf.integrity.index.IntegrityIndex` row per event
   (``event_uid -> (ledger_seq, leaf_index)``) so an inclusion proof can be
   rebuilt later without a rescan.

Metrics: ``ulpf_integrity_batches_sealed_total{trigger}`` and
``ulpf_integrity_batch_seal_seconds``.

With ``integrity.enabled`` false, or no signing key configured, the stage is a
pure pass-through.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from pathlib import Path

from ulpf.config.settings import Settings
from ulpf.core.metrics import INTEGRITY_BATCH_SEAL_SECONDS, INTEGRITY_BATCHES_SEALED
from ulpf.core.models import RawEvent
from ulpf.core.pipeline import Event
from ulpf.integrity.index import IntegrityIndex
from ulpf.integrity.ledger import IntegrityLedger, LedgerEntry
from ulpf.integrity.signing import Signer

_log = logging.getLogger(__name__)

_INDEX_FILENAME = "event_index.sqlite"
_MAX_POLL_SECONDS = 1.0


class IntegrityStage:
    """Accumulate raw-event hashes and seal them into the signed ledger in batches."""

    name = "integrity"

    def __init__(
        self,
        settings: Settings,
        *,
        signer: Signer | None,
        ledger: IntegrityLedger | None = None,
        index: IntegrityIndex | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """Build the ledger + index (unless disabled or no ``signer`` is given)."""
        cfg = settings.integrity
        self._enabled = bool(cfg.enabled and signer is not None)
        self._batch_size = max(int(cfg.batch_size), 1)
        self._timeout_s = max(float(cfg.batch_timeout_seconds), 0.0)
        self._monotonic = monotonic

        self._pending: list[tuple[str, bytes]] = []  # (event_uid, leaf hash)
        self._batch_started_at: float | None = None
        self._watcher: asyncio.Task[None] | None = None
        self._closed = False

        if self._enabled:
            assert signer is not None
            self._ledger = ledger or IntegrityLedger(settings, signer)
            index_path = Path(settings.storage.ledger_path) / _INDEX_FILENAME
            self._index = index or IntegrityIndex(index_path)
        else:
            self._ledger = None
            self._index = None
            _log.info("integrity stage disabled (integrity.enabled off or no signing key)")

    async def process(self, event: Event) -> Event:
        """Accumulate ``event.raw_hash``; pass the event through unchanged."""
        assert isinstance(event, RawEvent)
        if not self._enabled or self._closed:
            return event
        self._ensure_watcher()
        if not self._pending:
            self._batch_started_at = self._monotonic()
        self._pending.append((event.event_uid, bytes.fromhex(event.raw_hash)))
        if len(self._pending) >= self._batch_size:
            self._seal("size")
        return event

    async def flush(self) -> None:
        """Seal the partial batch and release resources (called on shutdown)."""
        self._closed = True
        if self._watcher is not None:
            self._watcher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._watcher
            self._watcher = None
        if self._enabled:
            self._seal("shutdown")
            assert self._index is not None
            self._index.close()

    # -- introspection (tests / API) ----------------------------------

    @property
    def enabled(self) -> bool:
        """Whether integrity sealing is active."""
        return self._enabled

    @property
    def ledger(self) -> IntegrityLedger | None:
        """The signed ledger (``None`` when disabled)."""
        return self._ledger

    @property
    def index(self) -> IntegrityIndex | None:
        """The per-event index (``None`` when disabled)."""
        return self._index

    def pending_count(self) -> int:
        """Events accumulated but not yet sealed."""
        return len(self._pending)

    # -- internals ------------------------------------------------------

    def _ensure_watcher(self) -> None:
        """Start the timeout poll once, lazily, on the running event loop."""
        if self._watcher is None and self._timeout_s > 0 and not self._closed:
            self._watcher = asyncio.ensure_future(self._watch())

    async def _watch(self) -> None:
        """Poll for a timed-out batch while traffic is quiet."""
        poll = min(self._timeout_s, _MAX_POLL_SECONDS) or _MAX_POLL_SECONDS
        try:
            while not self._closed:
                await asyncio.sleep(poll)
                if self._timed_out():
                    self._seal("timeout")
        except asyncio.CancelledError:
            pass

    def _timed_out(self) -> bool:
        """True when the open batch is older than the configured timeout."""
        return (
            bool(self._pending)
            and self._batch_started_at is not None
            and self._monotonic() - self._batch_started_at >= self._timeout_s
        )

    def _seal(self, trigger: str) -> LedgerEntry | None:
        """Fold the pending batch into a signed ledger entry + index rows."""
        if not self._pending or not self._enabled:
            return None
        assert self._ledger is not None and self._index is not None

        started = time.perf_counter()
        pending, self._pending = self._pending, []
        self._batch_started_at = None

        event_uids = [uid for uid, _ in pending]
        leaves = [leaf for _, leaf in pending]
        entry = self._ledger.append_batch(leaves, event_uids=event_uids)
        self._index.add_batch(entry.seq, event_uids)

        INTEGRITY_BATCH_SEAL_SECONDS.observe(time.perf_counter() - started)
        INTEGRITY_BATCHES_SEALED.labels(trigger=trigger).inc()
        _log.info(
            "integrity batch sealed",
            extra={"seq": entry.seq, "leaves": len(leaves), "trigger": trigger},
        )
        return entry
