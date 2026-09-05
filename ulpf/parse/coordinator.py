"""Parse coordinator — sniff, strip the syslog envelope, dispatch to an engine.

``ParseCoordinator.parse`` takes a :class:`~ulpf.core.models.RawEvent` and
returns a :class:`~ulpf.core.models.ParsedEvent`:

1. Decode the raw bytes to ``str`` with ``errors="replace"`` for detection and
   parsing, stripping a leading UTF-8/UTF-16 BOM from that working copy (see
   :func:`ulpf.parse.decode.decode_raw`; ``ParsedEvent.bom_stripped`` records
   it). The original bytes on the event are never touched.
2. :func:`~ulpf.detect.sniffer.sniff_layered` gives ``(outer, inner)``. This is
   FORMAT DETECTION ONLY — its one job is to name a shape so
   :class:`~ulpf.parse.dsl.loader.SourceRegistry` can match the right source
   definition. It never has, and must never be given, a source's own
   configuration (a ``csv`` engine's ``columns``, a ``grok`` engine's
   ``pattern``) — that belongs to the definition, not to detection.
3. If the outer format is syslog, strip the envelope (over the *bytes*, losslessly)
   and keep the parsed envelope on the ``ParsedEvent``.
4. Dispatch the remaining message to the engine registered for the **inner**
   format — but ONLY for a format that is genuinely self-describing and
   config-free (``json``, ``kv``, ``cef``, ``leef``). ``csv`` and ``tsv`` are
   never dispatched here even though engines exist for them, because both
   engines fundamentally require configuration only a matched source
   definition owns (see ``_NO_ENGINE_FORMATS`` below); ``unknown``/``grok``/
   ``dissect`` never had an engine to dispatch to in the first place.
5. Whenever no engine was dispatched (``unknown``, or a format that needs
   config it doesn't have), set ``fields = {}`` and flag
   ``needs_template_mining`` for Drain3 in Phase 7.
6. Any exception from a dispatched engine is re-raised as :class:`ParseError`
   carrying the ``format`` and a ``reason`` — this can now only happen for a
   genuinely malformed ``json``/``kv``/``cef``/``leef`` line, never for "this
   format needs configuration I don't have".

The envelope is also merged into ``fields`` under an ``envelope.`` prefix (via
:func:`~ulpf.parse.engines.util.flatten`) so no envelope datum is lost.

THE INTENDED FLOW: sniff -> match -> parse once
------------------------------------------------
This sniff-based pass is necessarily a **guess**, and by design a cheap and
safe one: it never attempts a parse that could fail only because a source's
own configuration is missing. Once :class:`SourceRegistry` has matched a
:class:`~ulpf.parse.dsl.schema.SourceDefinition` — using this pass's fields
where a ``field_equals`` detect rule needs them (e.g. Suricata EVE's
``event_type``), or purely the raw text otherwise (``contains``/``regex``/
``field_count``, as every ``csv``-based definition's detect rule does) —
:func:`parse_for_definition` below is the **one, authoritative parse**, using
that definition's own declared engine and options.
:class:`~ulpf.normalize.stage.NormalizeStage` always calls it exactly once a
source matches; ``ulpf inspect`` / ``ulpf sources verify`` / ``ulpf verify
roundtrip`` call the very same function, so none of them can disagree with
what the live pipeline actually does, or misreport a source whose format
needs per-definition configuration (a version-keyed ``column_map``, say) as
"parser non-determinism" merely because the config-free sniff pass above
could not read it.

A definition-less, purely speculative parse — this module's ``parse()``
below, with no definition in the picture at all — is reserved for the one
case where there is no definition to be authoritative about: a line that
matched no source at all, which is exactly the ``source_type="unknown"``
passthrough that feeds Drain3 template mining.
"""

from __future__ import annotations

from typing import Any

from ulpf.core.errors import ParseError, UlpfError
from ulpf.core.models import LogFormat, ParsedEvent, RawEvent
from ulpf.detect.sniffer import Sniffer, sniff_layered
from ulpf.parse.decode import decode_raw, strip_bom_bytes
from ulpf.parse.dsl.schema import SourceDefinition
from ulpf.parse.engines.base import ParseEngine
from ulpf.parse.engines.util import flatten
from ulpf.parse.registry import EngineRegistry
from ulpf.parse.registry import registry as _default_registry
from ulpf.parse.syslog_envelope import parse_syslog_envelope

# Formats the sniff-based pass never engine-dispatches, even speculatively.
#
# "unknown"/"syslog" have no engine at all. "csv" and "tsv" DO have engines,
# but both engines fundamentally REQUIRE configuration only a matched source
# definition owns (csv: a "columns" list or "column_map"; tsv: a "columns"
# option or a remembered "#fields" header from the same stream) — there is no
# generic, config-free way to parse them. Attempting it anyway is exactly the
# design flaw this set exists to prevent: PAN-OS TRAFFIC (csv) would sniff as
# "csv", the engine would raise "requires a 'columns' list", and that
# ParseError would count as a real parse failure — corrupting
# ulpf_parse_success_rate and "verify roundtrip"'s reparse_stable_rate for
# every event of a perfectly healthy, well-understood source, and logging one
# spurious INFO line per event. json/kv/cef/leef are left dispatchable here
# because they are genuinely self-describing: nothing outside the line itself
# is needed to extract fields from them, so speculatively parsing them costs
# nothing and is what lets a `field_equals` detect rule (e.g. Suricata EVE's
# alert vs. flow) match before any source definition is known.
_NO_ENGINE_FORMATS = frozenset({"unknown", "syslog", "csv", "tsv"})


def parse_for_definition(
    raw: bytes, definition: SourceDefinition, *, registry: EngineRegistry | None = None
) -> dict[str, Any]:
    """Parse ``raw`` with ``definition``'s own declared engine, options, and envelope handling.

    This is the one, shared, authoritative parse for an already-matched source
    — see the module docstring for why the sniff-based pass cannot be trusted
    for every source. Strips the syslog envelope when
    ``definition.parse.envelope == "syslog"`` and merges it into the returned
    fields under an ``envelope.`` prefix, exactly like the sniff-based pass.

    Raises:
        ParseError: The engine could not parse ``raw`` (never a bare engine
            exception).
    """
    reg = registry or _default_registry
    reg.load_engine_modules()
    spec = definition.parse
    text, bom_stripped = decode_raw(raw)
    raw_bytes = strip_bom_bytes(raw) if bom_stripped else raw

    envelope: dict[str, Any] = {}
    payload = text
    if spec.envelope == "syslog":
        envelope, message = parse_syslog_envelope(raw_bytes)
        payload = (
            text if spec.engine in ("cef", "leef") else message.decode("utf-8", errors="replace")
        )

    try:
        engine = reg.get(spec.engine)
    except KeyError as exc:
        raise ParseError(
            f"no parse engine registered as {spec.engine!r}", detail={"format": spec.engine}
        ) from exc
    try:
        fields = dict(engine.parse(payload, spec.options))
    except Exception as exc:  # noqa: BLE001 - every engine failure becomes ParseError
        reason = exc.detail.get("reason") if isinstance(exc, UlpfError) else type(exc).__name__
        raise ParseError(
            f"{spec.engine} engine failed",
            detail={"format": spec.engine, "reason": reason or str(exc), "error": str(exc)},
        ) from exc

    if envelope:
        fields.update(flatten(envelope, prefix="envelope"))
    return fields


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
        # Decode boundary: a leading BOM is removed from this working copy only.
        # raw_event.raw / raw_hash keep the BOM — it is part of the evidence.
        text, bom_stripped = decode_raw(raw_event.raw)
        outer, inner = self._sniff(raw_event.source_id, text)

        envelope: dict[str, Any] = {}
        payload = text
        if outer == "syslog":
            envelope_bytes = strip_bom_bytes(raw_event.raw) if bom_stripped else raw_event.raw
            envelope, message_bytes = parse_syslog_envelope(envelope_bytes)
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
            bom_stripped=bom_stripped,
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
