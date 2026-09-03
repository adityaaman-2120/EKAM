"""``NormalizeStage`` — the pipeline stage that produces OCSF records.

It sits after :class:`~ulpf.core.pipeline.ParseStage`:

1. :meth:`~ulpf.parse.dsl.loader.SourceRegistry.match` finds the
   :class:`~ulpf.parse.dsl.schema.SourceDefinition` for the event. If none
   matches, the event is passed through with ``source_type="unknown"`` (its
   fields kept for Phase 7 Drain3 template mining) — **not** dead-lettered.
2. :meth:`~ulpf.normalize.mapper.Mapper.apply` maps the flat fields to a nested
   OCSF record. A :class:`~ulpf.core.errors.MappingError` (e.g. a required field
   that would not coerce) dead-letters the event with the full parsed field
   dict and the partially-built OCSF record in ``detail`` — the extracted
   fields are never discarded.
3. :func:`~ulpf.normalize.ocsf.base.finalize` fills the derived name fields and
   strips ``None`` values.
4. :meth:`~ulpf.normalize.validator.OcsfValidator.validate` checks the record.
   If it fails and the source's ``validate.on_failure`` is ``"dead_letter"``,
   the event is dead-lettered with the validation errors in ``detail``;
   ``"warn"`` logs and emits the record anyway.
5. A :class:`~ulpf.core.models.NormalizedEvent` is built, carrying
   ``event_uid`` / ``raw_hash`` / ``mapping_version``.

Each emitted record increments
``ulpf_events_normalized_total{source_type,class_uid}``.
"""

from __future__ import annotations

import logging

from ulpf.config.settings import Settings
from ulpf.core.errors import MappingError
from ulpf.core.metrics import EVENTS_NORMALIZED
from ulpf.core.models import NormalizedEvent, ParsedEvent
from ulpf.core.pipeline import Event
from ulpf.normalize.mapper import Mapper
from ulpf.normalize.ocsf.base import finalize
from ulpf.normalize.validator import OcsfValidator
from ulpf.parse.dsl.loader import SourceRegistry
from ulpf.parse.dsl.schema import SourceDefinition
from ulpf.sinks.dlq import DeadLetterQueue

_log = logging.getLogger(__name__)


class NormalizeStage:
    """Match a source definition, map to OCSF, finalize, and validate."""

    name = "normalize"

    def __init__(
        self,
        settings: Settings,
        registry: SourceRegistry,
        *,
        mapper: Mapper | None = None,
        validator: OcsfValidator | None = None,
    ) -> None:
        """Wire the source registry, mapper, validator and a dead-letter queue."""
        self._registry = registry
        self._mapper = mapper or Mapper()
        self._validator = validator or OcsfValidator()
        self._dlq = DeadLetterQueue(settings)

    async def process(self, event: Event) -> NormalizedEvent | None:
        """Normalize one parsed event, or ``None`` if it was dead-lettered."""
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

        result = self._validator.validate(ocsf)
        if not result.valid:
            if definition.validation.on_failure == "dead_letter":
                self._dlq.write(
                    event,
                    reason="ocsf_validation_failed",
                    stage=self.name,
                    detail={"source_type": definition.name, "errors": result.errors},
                )
                return None
            _log.warning(
                "normalized record failed validation (on_failure=warn); emitting anyway",
                extra={
                    "source_type": definition.name,
                    "event_uid": event.event_uid,
                    "errors": result.errors,
                },
            )

        class_uid = ocsf.get("class_uid")
        EVENTS_NORMALIZED.labels(
            source_type=definition.name,
            class_uid=str(class_uid) if class_uid is not None else "unknown",
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
            source_type="unknown",
            mapping_version="none",
            enrichment={"needs_template_mining": event.needs_template_mining},
        )
