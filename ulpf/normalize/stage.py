"""Normalization stages: :class:`NormalizeStage` then :class:`ValidateStage`.

They are split so :class:`~ulpf.enrich.stage.EnrichStage` can run *between* them
— an enricher may promote a value into a proper OCSF slot that should then be
validated.

:class:`NormalizeStage` (after :class:`~ulpf.core.pipeline.ParseStage`):

1. :meth:`~ulpf.parse.dsl.loader.SourceRegistry.match` finds the source
   definition. No match -> the event is passed through as
   ``source_type="unknown"`` (fields kept for Drain3) — **not** dead-lettered.
2. :meth:`~ulpf.normalize.mapper.Mapper.apply` maps the flat fields to a nested
   OCSF record; a :class:`~ulpf.core.errors.MappingError` dead-letters the event
   with the parsed fields and partial record in ``detail``.
3. :func:`~ulpf.normalize.ocsf.base.finalize` fills derived name fields.
4. A :class:`~ulpf.core.models.NormalizedEvent` is emitted and
   ``ulpf_events_normalized_total{source_type,class_uid}`` incremented.

:class:`ValidateStage` (after :class:`~ulpf.enrich.stage.EnrichStage`):

* runs :class:`~ulpf.normalize.validator.OcsfValidator`; a valid record passes
  through untouched;
* an invalid record whose source definition says ``on_failure: dead_letter`` is
  dead-lettered (``stage="validate"``) and dropped — the original bytes remain
  in bronze under ``raw_hash``; ``on_failure: warn`` logs and emits it anyway;
* pass-through (``source_type="unknown"``) records are not validated.
"""

from __future__ import annotations

import logging

from ulpf.config.settings import Settings
from ulpf.core.errors import MappingError
from ulpf.core.metrics import EVENTS_NORMALIZED
from ulpf.core.models import NormalizedEvent, ParsedEvent, RawEvent
from ulpf.core.pipeline import Event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import SourceDefinition
from ulpf.sinks.dlq import DeadLetterQueue

_log = logging.getLogger(__name__)

_UNKNOWN = "unknown"


class NormalizeStage:
    """Match a source definition, map to OCSF, and finalize."""

    name = "normalize"

    def __init__(
        self, settings: Settings, registry: SourceRegistry, *, mapper: Mapper | None = None
    ) -> None:
        """Wire the source registry, mapper, and a dead-letter queue."""
        self._registry = registry
        self._mapper = mapper or Mapper()
        self._dlq = DeadLetterQueue(settings)

    async def process(self, event: Event) -> NormalizedEvent | None:
        """Normalize one parsed event, or ``None`` if a mapping failure dead-lettered it."""
        assert isinstance(event, ParsedEvent)
        definition = self._registry.match(event)
        if definition is None:
            return self._passthrough(event)

        try:
            ocsf = finalize(
                self._mapper.apply(
                    definition, event.fields, event_uid=event.event_uid, raw_hash=event.raw_hash
                )
            )
        except MappingError as exc:
            self._dead_letter_mapping_failure(event, definition, exc)
            return None

        class_uid = ocsf.get("class_uid")
        EVENTS_NORMALIZED.labels(
            source_type=definition.name,
            class_uid=str(class_uid) if class_uid is not None else _UNKNOWN,
        ).inc()
        return NormalizedEvent(
            event_uid=event.event_uid,
            raw_hash=event.raw_hash,
            ingest_time_ns=event.ingest_time_ns,
            ocsf=ocsf,
            source_type=definition.name,
            mapping_version=definition.version,
            enrichment={},
        )

    def _dead_letter_mapping_failure(
        self, event: ParsedEvent, definition: SourceDefinition, exc: MappingError
    ) -> None:
        """Dead-letter a mapping failure, keeping the parsed fields and partial record.

        The raw event is already in bronze; this makes the DLQ entry show *what
        was parsed* and *how far mapping got*, so an operator can fix the source
        definition without replaying the log.
        """
        detail = dict(exc.detail)
        detail.setdefault("parsed_fields", dict(event.fields))
        detail.setdefault("partial_ocsf", {})
        self._dlq.write(
            event,
            reason=str(detail.get("reason") or "mapping_failed"),
            stage=self.name,
            detail={"source_type": definition.name, "error": str(exc), **detail},
        )
        _log.warning(
            "mapping failed; event dead-lettered with parsed fields",
            extra={
                "source_type": definition.name,
                "event_uid": event.event_uid,
                "target": detail.get("target"),
                "field_count": len(event.fields),
            },
        )

    def _passthrough(self, event: ParsedEvent) -> NormalizedEvent:
        """No source matched: keep the fields (for Drain3 later), never dead-letter."""
        return NormalizedEvent(
            event_uid=event.event_uid,
            raw_hash=event.raw_hash,
            ingest_time_ns=event.ingest_time_ns,
            ocsf={
                "metadata": {"uid": event.event_uid, "log_hash": event.raw_hash},
                "unmapped": dict(event.fields),
            },
            source_type=_UNKNOWN,
            mapping_version="none",
            enrichment={"needs_template_mining": event.needs_template_mining},
        )


class ValidateStage:
    """Validate the (possibly enriched) OCSF record; dead-letter per source policy."""

    name = "validate"

    def __init__(
        self,
        settings: Settings,
        registry: SourceRegistry,
        *,
        validator: OcsfValidator | None = None,
    ) -> None:
        """Wire the validator, the registry (for the per-source policy) and the DLQ."""
        self._registry = registry
        self._validator = validator or OcsfValidator()
        self._dlq = DeadLetterQueue(settings)

    async def process(self, event: Event) -> NormalizedEvent | None:
        """Return the event if valid (or ``on_failure: warn``), else ``None``."""
        assert isinstance(event, NormalizedEvent)
        if event.source_type == _UNKNOWN or "class_uid" not in event.ocsf:
            return event  # pass-through / non-OCSF records are not validated

        result = self._validator.validate(event.ocsf)
        if result.valid:
            return event

        definition = self._registry.get(event.source_type)
        on_failure = (
            definition.validation.on_failure if definition is not None else "dead_letter"
        )
        if on_failure == "dead_letter":
            self._dlq.write(
                _raw_stub(event),
                reason="ocsf_validation_failed",
                stage=self.name,
                detail={
                    "source_type": event.source_type,
                    "errors": result.errors,
                    "note": "raw bytes are in the bronze store under raw_hash",
                },
            )
            _log.warning(
                "normalized record failed validation; dead-lettered",
                extra={"source_type": event.source_type, "event_uid": event.event_uid},
            )
            return None

        _log.warning(
            "normalized record failed validation (on_failure=warn); emitting anyway",
            extra={
                "source_type": event.source_type,
                "event_uid": event.event_uid,
                "errors": result.errors,
            },
        )
        return event


def _raw_stub(event: NormalizedEvent) -> RawEvent:
    """A minimal :class:`RawEvent` carrying the traceability keys for the DLQ.

    The original bytes are already in the bronze store keyed by ``raw_hash``; a
    post-normalization failure does not need to re-persist them.
    """
    return RawEvent(
        event_uid=event.event_uid,
        raw=b"",
        raw_hash=event.raw_hash,
        raw_len=0,
        ingest_time_ns=event.ingest_time_ns,
        source_id=event.source_type,
        transport="file",
    )
