"""Runtime assembly: the pipeline plus every configured listener, run as one unit.

``Runtime`` is the object ``ulpf run`` drives. It builds a single
:class:`~ulpf.core.pipeline.Pipeline` (``RawStoreStage`` -> ``IntegrityStage`` ->
``ParseStage`` -> ``NormalizeStage`` -> ``EnrichStage`` -> ``ValidateStage``),
points every listener's ``on_event`` at :meth:`Pipeline.submit`, and manages
orderly startup and shutdown. ``IntegrityStage`` sits right after the raw-store
write so the signed Merkle ledger covers the untouched evidence. The enricher
chain (network context, GeoIP, threat intel, ATT&CK tagging) is assembled from
``settings.enrich`` and its per-enricher status is served on the intake app's
``GET /health``.

* **start**  — pipeline workers, then the syslog UDP/TCP listeners, the syslog
  TLS listener (only if ``tls.cert_path``/``key_path`` are set), a file tailer
  (only if ``ingest.file_tail_paths`` is non-empty), and the HTTP intake app on
  ``ingest.http_port`` (served by an embedded uvicorn that does *not* install its
  own signal handlers).
* **stop**   — stop the listeners first so their in-flight events reach the
  queue, then :meth:`Pipeline.stop` drains the queue and flushes the sinks.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Awaitable, Callable

import uvicorn

from ulpf.config.settings import Settings
from ulpf.core.models import RawEvent
from ulpf.core.pipeline import ParseStage, Pipeline, RawStoreStage
from ulpf.enrich.factory import build_enrichers, describe_enrichers
from ulpf.enrich.pipeline import EnrichmentPipeline
from ulpf.enrich.stage import EnrichStage
from ulpf.enrich.threat_intel import ThreatIntelEnricher
from ulpf.ingest.file_tail import FileTailer
from ulpf.ingest.http_intake import create_intake_app
from ulpf.ingest.syslog_tcp import SyslogTcpListener
from ulpf.ingest.syslog_tls import SyslogTlsListener
from ulpf.ingest.syslog_udp import SyslogUdpListener
from ulpf.integrity.signing import Signer
from ulpf.integrity.stage import IntegrityStage
from ulpf.normalize.stage import NormalizeStage, ValidateStage
from ulpf.parse.coordinator import ParseCoordinator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.sinks.raw_store import RawStore

_log = logging.getLogger(__name__)

_BIND_HOST = "0.0.0.0"
_Submit = Callable[[RawEvent], Awaitable[None]]
_OnStarted = Callable[["Runtime"], None]


class _NoSignalServer(uvicorn.Server):
    """Embedded uvicorn server; signal handling belongs to :class:`Runtime`."""

    def install_signal_handlers(self) -> None:
        """Do nothing — the Runtime owns SIGINT/SIGTERM."""
        return None


def _load_signing_key(settings: Settings) -> Signer | None:
    """Load the integrity-ledger signing key, or ``None`` (integrity self-disables)."""
    integrity = settings.integrity
    if not integrity.enabled:
        return None
    key_path = integrity.signing_key_path
    if key_path is None or not key_path.is_file():
        _log.warning(
            "integrity.enabled but no signing key at %s; the integrity ledger is OFF "
            "(run `ulpf keys generate` and set integrity.signing_key_path)",
            key_path,
        )
        return None
    return Signer.load(key_path)


class Runtime:
    """Owns the pipeline and all listeners for a single ULPF process."""

    def __init__(self, settings: Settings) -> None:
        """Build the pipeline and listener objects (nothing is bound yet)."""
        self._settings = settings
        self._raw_store = RawStore(settings)
        self._coordinator = ParseCoordinator()
        self._sources = SourceRegistry()
        sources_dir = settings.parse.sources_dir
        sources_dir.mkdir(parents=True, exist_ok=True)
        self._sources.load_all(sources_dir)
        self._enrichers = build_enrichers(settings)
        self._enrich = EnrichmentPipeline(settings, self._enrichers)
        self._integrity = IntegrityStage(settings, signer=_load_signing_key(settings))
        self._pipeline = Pipeline(
            settings,
            [
                RawStoreStage(self._raw_store),
                # integrity covers the RAW evidence, before parsing can alter it
                self._integrity,
                ParseStage(settings, self._coordinator),
                NormalizeStage(settings, self._sources),
                EnrichStage(settings, self._enrich),
                ValidateStage(settings, self._sources),
            ],
        )
        self._udp = SyslogUdpListener()
        self._tcp = SyslogTcpListener()
        self._tls: SyslogTlsListener | None = None
        self._tailer: FileTailer | None = None
        self._http: _NoSignalServer | None = None
        self._bg: list[asyncio.Task[None]] = []

    @property
    def pipeline(self) -> Pipeline:
        """The underlying pipeline (for introspection/tests)."""
        return self._pipeline

    @property
    def udp_port(self) -> int:
        """Bound UDP port (useful when configured as 0)."""
        return int(self._udp.sockname[1])

    @property
    def tcp_port(self) -> int:
        """Bound TCP port (useful when configured as 0)."""
        return int(self._tcp.sockname[1])

    @property
    def tls_port(self) -> int | None:
        """Bound TLS port, or ``None`` when the TLS listener is disabled."""
        return int(self._tls.sockname[1]) if self._tls is not None else None

    def enricher_status(self) -> list[dict[str, object]]:
        """Per-enricher name / enabled / ready / detail — surfaced on ``/health``."""
        return describe_enrichers(self._settings, self._enrichers)

    async def start(self) -> None:
        """Start the pipeline, then bind every configured listener."""
        ingest = self._settings.ingest
        submit: _Submit = self._pipeline.submit
        self._sources.start_watching()  # hot-reload source definitions (requirement e)
        for enricher in self._enrichers:  # hot-reload IOC files (threat_intel)
            if isinstance(enricher, ThreatIntelEnricher):
                enricher.start()
        self._pipeline.start()
        await self._udp.start(_BIND_HOST, ingest.syslog_udp_port, submit)
        await self._tcp.start(_BIND_HOST, ingest.syslog_tcp_port, submit)
        if self._settings.tls.cert_path and self._settings.tls.key_path:
            self._tls = SyslogTlsListener.from_settings(self._settings)
            await self._tls.start(_BIND_HOST, ingest.syslog_tls_port, submit)
        else:
            _log.info("syslog TLS listener disabled (no tls.cert_path/key_path)")
        if ingest.file_tail_paths:
            self._tailer = FileTailer(self._settings)
            self._bg.append(
                asyncio.create_task(self._tailer.watch(list(ingest.file_tail_paths), submit))
            )
        await self._start_http(submit)

    async def _start_http(self, submit: _Submit) -> None:
        """Launch the embedded uvicorn serving the HTTP intake app."""
        config = uvicorn.Config(
            create_intake_app(self._settings, submit, health=self.enricher_status),
            host=_BIND_HOST,
            port=self._settings.ingest.http_port,
            log_level="warning",
            lifespan="off",
            access_log=False,
        )
        self._http = _NoSignalServer(config)
        self._bg.append(asyncio.create_task(self._http.serve()))
        for _ in range(500):
            if self._http.started:
                return
            await asyncio.sleep(0.01)
        raise RuntimeError("HTTP intake server failed to start")

    async def stop(self) -> None:
        """Stop listeners (letting their in-flight events land), then the pipeline."""
        await self._udp.stop()
        await self._tcp.stop()
        if self._tls is not None:
            await self._tls.stop()
        if self._tailer is not None:
            self._tailer.stop()
        if self._http is not None:
            self._http.should_exit = True
        for task in self._bg:
            with contextlib.suppress(asyncio.CancelledError, TimeoutError):
                await asyncio.wait_for(task, timeout=5.0)
        self._bg.clear()
        self._sources.stop_watching()
        for enricher in self._enrichers:
            if isinstance(enricher, ThreatIntelEnricher):
                enricher.stop()
        self._enrich.close()
        await self._pipeline.stop()

    async def serve(self, on_started: _OnStarted | None = None) -> None:
        """Start everything, wait for SIGINT/SIGTERM (or cancellation), then stop."""
        await self.start()
        if on_started is not None:
            on_started(self)
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        self._install_signal_handlers(loop, stop_event)
        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    @staticmethod
    def _install_signal_handlers(
        loop: asyncio.AbstractEventLoop, stop_event: asyncio.Event
    ) -> None:
        """Wire SIGINT/SIGTERM to ``stop_event`` on any platform.

        ``loop.add_signal_handler`` is Unix-only; on Windows fall back to
        ``signal.signal`` (SIGINT works there) so Ctrl-C still shuts down cleanly.
        """
        signals = [signal.SIGINT, signal.SIGTERM]
        if hasattr(signal, "SIGBREAK"):  # Windows Ctrl-Break / CTRL_BREAK_EVENT
            signals.append(signal.SIGBREAK)
        for sig in signals:
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except (NotImplementedError, AttributeError, ValueError, RuntimeError):
                with contextlib.suppress(ValueError, OSError, RuntimeError):
                    signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop_event.set))
