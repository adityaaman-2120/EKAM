"""Parse coordinator — sniff, strip the syslog envelope, dispatch to an engine.

``ParseCoordinator.parse`` takes a :class:`~ulpf.core.models.RawEvent` and
returns a :class:`~ulpf.core.models.ParsedEvent`:

1. Decode the raw bytes to ``str`` with ``errors="replace"`` for detection and
   parsing. The original bytes on the event are never touched.
2. :func:`~ulpf.detect.sniffer.sniff_layered` gives ``(outer, inner)``.
3. If the outer format is syslog, strip the envelope (over the *bytes*, losslessly)
   and keep the parsed envelope on the ``ParsedEvent``.
4. Dispatch the remaining message to the engine registered for the **inner**
   format.
5. If that format is ``unknown`` (or has no engine, e.g. a bare syslog line
   whose body is free text), set ``fields = {}`` and flag
   ``needs_template_mining`` for Drain3 in Phase 7.
6. Any exception from an engine is re-raised as :class:`ParseError` carrying the
   ``format`` and a ``reason``.

The envelope is also merged into ``fields`` under an ``envelope.`` prefix (via
:func:`~ulpf.parse.engines.util.flatten`) so no envelope datum is lost.
"""

from __future__ import annotations

from typing import Any

from ulpf.core.errors import ParseError, UlpfError
from ulpf.core.models import LogFormat, ParsedEvent, RawEvent
from ulpf.detect.sniffer import Sniffer, sniff_layered
from ulpf.parse.engines.base import ParseEngine
from ulpf.parse.engines.util import flatten
from ulpf.parse.registry import EngineRegistry
from ulpf.parse.registry import registry as _default_registry
from ulpf.parse.syslog_envelope import parse_syslog_envelope

_NO_ENGINE_FORMATS = frozenset({"unknown", "syslog"})


class ParseCoordinator:
    """Ties detection, envelope stripping and engine dispatch into one step."""

    def __init__(
        self,
        *,
        registry: EngineRegistry | None = None,
        engine_options: dict[str, dict[str, Any]] | None = None,
        sniffer: Sniffer | None = None,
    ) -> None:
        """Configure the coordinator.

        Args:
            registry: Engine registry to dispatch through (default: the global one).
            engine_options: Per-format options passed to the engine, e.g.
                ``{"csv": {"columns": [...]}, "grok": {"pattern": "..."}}``.
            sniffer: Optional per-source-cached :class:`Sniffer`; when omitted,
                :func:`sniff_layered` is called per line.
        """
        self._registry = registry or _default_registry
        self._registry.load_engine_modules()  # ensure the built-in engines are registered
        self._engine_options = engine_options or {}
        self._sniffer = sniffer

    def parse(self, raw_event: RawEvent) -> ParsedEvent:
        """Detect, strip, and parse ``raw_event`` into a :class:`ParsedEvent`."""
        text = raw_event.raw.decode("utf-8", errors="replace")
        outer, inner = self._sniff(raw_event.source_id, text)

        envelope: dict[str, Any] = {}
        payload = text
        if outer == "syslog":
            envelope, message_bytes = parse_syslog_envelope(raw_event.raw)
            payload = message_bytes.decode("utf-8", errors="replace")
            if inner in ("cef", "leef"):
                # CEF/LEEF engines self-locate their marker; hand them the whole
                # line so a syslog TAG that swallowed "CEF:"/"LEEF:" is harmless.
                payload = text

        fmt: LogFormat = inner  # type: ignore[assignment]  # sniffer output == LogFormat values
        engine = self._engine_for(fmt)
        if engine is None:
            fields: dict[str, Any] = {}
            needs_mining = True
        else:
            fields = self._run_engine(engine, fmt, payload)
            needs_mining = False

        merged = dict(fields)
        if envelope:
            merged.update(flatten(envelope, prefix="envelope"))

        return ParsedEvent(
            **raw_event.model_dump(),
            format=fmt,
            source_type=None,
            fields=merged,
            envelope=envelope,
            needs_template_mining=needs_mining,
        )

    def _sniff(self, source_id: str, text: str) -> tuple[str, str]:
        """Return ``(outer, inner)`` formats, using the cached sniffer if present."""
        if self._sniffer is not None:
            return self._sniffer.sniff_source_layered(source_id, text)
        return sniff_layered(text)

    def _engine_for(self, fmt: str) -> ParseEngine | None:
        """The engine for ``fmt``, or ``None`` for ``unknown``/no registered engine."""
        if fmt in _NO_ENGINE_FORMATS:
            return None
        try:
            return self._registry.get(fmt)
        except KeyError:
            return None

    def _run_engine(self, engine: ParseEngine, fmt: str, payload: str) -> dict[str, Any]:
        """Run ``engine`` on ``payload``; normalize any failure to ``ParseError``."""
        options = self._engine_options.get(fmt, {})
        try:
            return dict(engine.parse(payload, options))
        except Exception as exc:  # noqa: BLE001 - every engine failure becomes ParseError
            reason = exc.detail.get("reason") if isinstance(exc, UlpfError) else type(exc).__name__
            raise ParseError(
                "parse engine failed",
                detail={"format": fmt, "reason": reason or str(exc), "error": str(exc)},
            ) from exc
