"""Source-definition registry with validate-before-swap hot reload.

This is what makes requirement *e* (plug-and-play onboarding) real: adding a
perimeter log source is **one YAML file, no restart**. :class:`SourceRegistry`
loads every ``*.yaml`` in ``configs/sources/``, validates each against
:class:`~ulpf.parse.dsl.schema.SourceDefinition`, and — while a watchdog observer
is running — reloads on change.

The reload is **validate-then-atomically-swap**: a changed file is parsed and
validated *before* it can enter the live registry, and the swap is a single
reference reassignment. A malformed or schema-invalid file therefore can never
take down a running pipeline — the error is logged and the previous definition
stays in force. ``reload_count`` / ``last_reload_time`` are exposed for the API
and dashboard.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import regex
import yaml
from pydantic import ValidationError
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ulpf.core.models import ParsedEvent
from ulpf.parse.dsl.schema import (
    DetectRule,
    FieldCount,
    SourceDefinition,
    load_source_definition,
)

_log = logging.getLogger(__name__)


def evaluate_detect(rule: DetectRule, raw_text: str, fields: Mapping[str, Any]) -> bool:
    """Evaluate one :class:`DetectRule` against the raw line and parsed fields."""
    if rule.contains is not None:
        return rule.contains in raw_text
    if rule.starts_with is not None:
        return raw_text.startswith(rule.starts_with)
    if rule.regex is not None:
        return regex.search(rule.regex, raw_text) is not None
    if rule.all is not None:
        return all(evaluate_detect(child, raw_text, fields) for child in rule.all)
    if rule.any is not None:
        return any(evaluate_detect(child, raw_text, fields) for child in rule.any)
    if rule.field_equals is not None:
        return _field_equals(fields, rule.field_equals.name, rule.field_equals.value)
    if rule.field_count is not None:
        return _field_count(rule.field_count, raw_text)
    return False  # unreachable: the schema guarantees exactly one alternative


def _field_count(rule: FieldCount, raw_text: str) -> bool:
    """Whether ``raw_text`` splits into a field count matching ``rule``."""
    n = raw_text.count(rule.delimiter) + 1
    if rule.equals is not None and n != rule.equals:
        return False
    if rule.min is not None and n < rule.min:
        return False
    return not (rule.max is not None and n > rule.max)


def _field_equals(fields: Mapping[str, Any], name: str, value: Any) -> bool:
    """Compare ``fields[name]`` to ``value`` exactly, then as strings."""
    if name not in fields:
        return False
    got = fields[name]
    return bool(got == value) or str(got) == str(value)


class SourceRegistry:
    """In-memory, hot-reloadable set of :class:`SourceDefinition` objects."""

    def __init__(self) -> None:
        """Create an empty registry (call :meth:`load_all` before use)."""
        self._dir: Path | None = None
        self._definitions: dict[str, SourceDefinition] = {}
        self._paths: dict[str, str] = {}  # file path -> definition name
        self._lock = threading.Lock()
        self._observer: Observer | None = None
        self._reload_count = 0
        self._last_reload_time: float | None = None

    # -- accessors -----------------------------------------------------

    @property
    def reload_count(self) -> int:
        """How many times the registry contents have changed."""
        return self._reload_count

    @property
    def last_reload_time(self) -> float | None:
        """Unix time of the last (re)load, or ``None`` if never loaded."""
        return self._last_reload_time

    def definitions(self) -> list[SourceDefinition]:
        """Every loaded definition, ordered by ``priority`` then ``name``."""
        return sorted(self._definitions.values(), key=lambda d: (d.priority, d.name))

    def get(self, name: str) -> SourceDefinition | None:
        """Return the definition registered as ``name``, if any."""
        return self._definitions.get(name)

    # -- loading -----------------------------------------------------

    def load_all(self, directory: Path | str) -> None:
        """Load and validate every ``*.yaml`` in ``directory`` into the registry."""
        self._dir = Path(directory)
        loaded: dict[str, SourceDefinition] = {}
        paths: dict[str, str] = {}
        for path in sorted(self._dir.glob("*.yaml")):
            definition = self._read_and_validate(path)
            if definition is not None:
                loaded[definition.name] = definition
                paths[str(path)] = definition.name
        with self._lock:
            self._definitions = loaded
            self._paths = paths
            self._bump_reload()
        _log.info("loaded source definitions", extra={"count": len(loaded)})

    def _read_and_validate(self, path: Path) -> SourceDefinition | None:
        """Parse + validate one file; log and return ``None`` on any failure."""
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("top-level YAML is not a mapping")
            return load_source_definition(data)
        except (OSError, yaml.YAMLError, ValidationError, ValueError) as exc:
            _log.error(
                "source definition rejected; keeping previous version",
                extra={"path": str(path), "error": str(exc)},
            )
            return None

    # -- matching -----------------------------------------------------

    def match(self, parsed_event: ParsedEvent) -> SourceDefinition | None:
        """Return the first (lowest-priority-number) definition whose detect matches."""
        raw_text = parsed_event.raw.decode("utf-8", "replace")
        return self.match_text(raw_text, parsed_event.fields)

    def match_text(self, raw_text: str, fields: Mapping[str, Any]) -> SourceDefinition | None:
        """Like :meth:`match` but from a decoded line and a field mapping."""
        for definition in self.definitions():
            if definition.enabled and evaluate_detect(definition.detect, raw_text, fields):
                return definition
        return None

    # -- watching -----------------------------------------------------

    def start_watching(self) -> None:
        """Begin watching the sources directory for changes (idempotent)."""
        if self._observer is not None or self._dir is None:
            return
        observer = Observer()
        observer.schedule(_ReloadHandler(self), str(self._dir), recursive=False)
        observer.start()
        self._observer = observer

    def stop_watching(self) -> None:
        """Stop the directory watcher."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

    def _on_file_changed(self, path: Path) -> None:
        """Handle a created/modified YAML file: validate, then atomically swap in."""
        definition = self._read_and_validate(path)
        if definition is None:
            return  # broken file — the live registry is left untouched
        with self._lock:
            updated = dict(self._definitions)
            previous = self._paths.get(str(path))
            if previous and previous != definition.name:
                updated.pop(previous, None)
            updated[definition.name] = definition
            self._definitions = updated
            self._paths[str(path)] = definition.name
            self._bump_reload()
        _log.info("source definition reloaded", extra={"name": definition.name})

    def _on_file_deleted(self, path: Path) -> None:
        """Handle a removed YAML file: drop its definition if it was loaded."""
        with self._lock:
            name = self._paths.pop(str(path), None)
            if name and name in self._definitions:
                updated = dict(self._definitions)
                updated.pop(name, None)
                self._definitions = updated
                self._bump_reload()
                _log.info("source definition removed", extra={"name": name})

    def _bump_reload(self) -> None:
        """Record that the registry contents changed (call under ``self._lock``)."""
        self._reload_count += 1
        self._last_reload_time = time.time()


class _ReloadHandler(FileSystemEventHandler):
    """Routes watchdog events for ``*.yaml`` files to the registry."""

    def __init__(self, registry: SourceRegistry) -> None:
        """Bind this handler to its ``registry``."""
        self._registry = registry

    def on_created(self, event: FileSystemEvent) -> None:
        """A new file appeared."""
        self._changed(event, event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        """A file's contents changed."""
        self._changed(event, event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        """A file was renamed into (or within) the directory."""
        self._changed(event, getattr(event, "dest_path", event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        """A file was removed."""
        if not event.is_directory and str(event.src_path).endswith(".yaml"):
            self._registry._on_file_deleted(Path(event.src_path))

    def _changed(self, event: FileSystemEvent, raw_path: object) -> None:
        """Forward a create/modify/move to the registry if it's a YAML file."""
        if event.is_directory:
            return
        path = Path(str(raw_path))
        if path.suffix == ".yaml":
            self._registry._on_file_changed(path)
