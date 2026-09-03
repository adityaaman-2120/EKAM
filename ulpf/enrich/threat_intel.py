"""Threat-intelligence enricher — match record observables against local IOC sets.

Indicator sets live as JSON files in ``configs/iocs/`` (path from
``settings.enrich.ioc_dir``). Each file is::

    {"type": "ip" | "domain" | "hash" | "cidr",
     "source": "<feed name>",
     "confidence": "<any scalar, optional>",
     "indicators": ["...", "..."]}

:class:`IndicatorStore` loads every file into **in-memory** structures at start
(a ``dict`` per exact-match type, a :class:`~ulpf.enrich._cidr.CidrTrie` for the
``cidr`` type) and **hot-reloads** on change using the same
validate-then-atomically-swap watchdog pattern as
:class:`ulpf.parse.dsl.loader.SourceRegistry` — a malformed file is logged and
skipped, the live set is never corrupted.

For each event :class:`ThreatIntelEnricher` checks the src/dst IP, every
hostname/domain field, and every hash field. The first match yields::

    {"threat_intel": {"matched": true, "indicator": ..., "ioc_type": ...,
                      "ioc_source": ..., "confidence": ..., "matched_on": ...}}

No network access at any point — everything is answered from the loaded sets, so
it works unchanged in an air-gapped deployment.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ulpf.config.settings import Settings
from ulpf.enrich._cidr import CidrTrie

_log = logging.getLogger(__name__)

_IOC_TYPES = ("ip", "domain", "hash", "cidr")
_HOST_KEYS = frozenset({"hostname", "domain", "fqdn"})
_HASH_KEYS = frozenset({"hash", "md5", "sha1", "sha256", "sha512", "imphash", "ssdeep"})


@dataclass(frozen=True)
class Indicator:
    """One compiled indicator plus the provenance to report on a hit."""

    value: str
    ioc_type: str
    source: str
    confidence: Any


@dataclass(frozen=True)
class IocFile:
    """A validated ``configs/iocs/*.json`` file."""

    ioc_type: str
    source: str
    confidence: Any
    indicators: tuple[str, ...]


def _normalise(ioc_type: str, item: str) -> str:
    """Canonicalise one raw indicator; raises ``ValueError`` if ip/cidr is malformed."""
    text = item.strip()
    if ioc_type == "ip":
        return str(ip_address(text))
    if ioc_type == "cidr":
        return str(ip_network(text, strict=False))
    return text.lower().rstrip(".")


class IndicatorSet:
    """An immutable, compiled snapshot of every loaded indicator."""

    def __init__(self, files: Iterable[IocFile]) -> None:
        """Build the exact-match dicts and the CIDR trie from parsed files."""
        self.ips: dict[str, Indicator] = {}
        self.domains: dict[str, Indicator] = {}
        self.hashes: dict[str, Indicator] = {}
        self._cidr: CidrTrie[Indicator] = CidrTrie()
        self._cidr_count = 0
        for ioc_file in files:
            self._ingest(ioc_file)

    def _ingest(self, ioc_file: IocFile) -> None:
        """Add one file's indicators to the right structure."""
        for value in ioc_file.indicators:
            ind = Indicator(value, ioc_file.ioc_type, ioc_file.source, ioc_file.confidence)
            if ioc_file.ioc_type == "ip":
                self.ips[value] = ind
            elif ioc_file.ioc_type == "domain":
                self.domains[value] = ind
            elif ioc_file.ioc_type == "hash":
                self.hashes[value] = ind
            else:  # cidr
                self._cidr.insert(ip_network(value, strict=False), ind)
                self._cidr_count += 1

    def __len__(self) -> int:
        """Total indicator count across every type."""
        return len(self.ips) + len(self.domains) + len(self.hashes) + self._cidr_count

    def counts(self) -> dict[str, int]:
        """Per-type indicator counts (for the API / dashboard)."""
        return {
            "ip": len(self.ips),
            "domain": len(self.domains),
            "hash": len(self.hashes),
            "cidr": self._cidr_count,
        }

    def match_ip(self, ip: str) -> Indicator | None:
        """Exact IP hit, then longest-prefix CIDR hit."""
        try:
            key = str(ip_address(ip))
        except ValueError:
            return None
        hit = self.ips.get(key)
        if hit is not None:
            return hit
        return self._cidr.lookup(key) if self._cidr_count else None

    def match_domain(self, host: str) -> Indicator | None:
        """Exact hostname hit, then each parent domain (never the bare TLD)."""
        if not self.domains:
            return None
        labels = host.strip().lower().rstrip(".").split(".")
        for start in range(max(len(labels) - 1, 1)):
            hit = self.domains.get(".".join(labels[start:]))
            if hit is not None:
                return hit
        return None

    def match_hash(self, digest: str) -> Indicator | None:
        """Case-insensitive exact hash hit."""
        return self.hashes.get(digest.strip().lower())


class IndicatorStore:
    """Hot-reloadable set of IOC files under one directory."""

    def __init__(self) -> None:
        """Create an empty store; call :meth:`load_all` before use."""
        self._dir: Path | None = None
        self._files: dict[str, IocFile] = {}
        self._set = IndicatorSet([])
        self._lock = threading.Lock()
        self._observer: Any = None
        self._reload_count = 0
        self._last_reload_time: float | None = None

    @property
    def reload_count(self) -> int:
        """How many times the compiled set has been (re)built."""
        return self._reload_count

    @property
    def last_reload_time(self) -> float | None:
        """Unix time of the last (re)build, or ``None`` if never loaded."""
        return self._last_reload_time

    @property
    def indicators(self) -> IndicatorSet:
        """The current compiled snapshot (atomic to read)."""
        return self._set

    # -- loading ------------------------------------------------------------

    def load_all(self, directory: Path | str) -> None:
        """Load and validate every ``*.json`` in ``directory`` into the store."""
        self._dir = Path(directory)
        files: dict[str, IocFile] = {}
        for path in sorted(self._dir.glob("*.json")):
            parsed = self._read_and_validate(path)
            if parsed is not None:
                files[str(path)] = parsed
        with self._lock:
            self._files = files
            self._rebuild_locked()
        _log.info(
            "loaded IOC files", extra={"files": len(files), "indicators": len(self._set)}
        )

    def _read_and_validate(self, path: Path) -> IocFile | None:
        """Parse + validate one file; log and return ``None`` on any failure."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            ioc_type = data["type"]
            if ioc_type not in _IOC_TYPES:
                raise ValueError(f"unknown IOC type {ioc_type!r}")
            raw = data["indicators"]
            if not isinstance(raw, list):
                raise TypeError("'indicators' must be a list")
            return IocFile(
                ioc_type=ioc_type,
                source=str(data["source"]),
                confidence=data.get("confidence", "unknown"),
                indicators=tuple(_normalise(ioc_type, str(item)) for item in raw),
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            _log.error(
                "IOC file rejected; keeping previous set",
                extra={"path": str(path), "error": str(exc)},
            )
            return None

    def _rebuild_locked(self) -> None:
        """Recompile ``self._set`` from ``self._files`` (call under ``self._lock``)."""
        self._set = IndicatorSet(self._files.values())
        self._reload_count += 1
        self._last_reload_time = time.time()

    # -- matching ---------------------------------------------------------

    def match(self, record: dict[str, Any]) -> dict[str, Any] | None:
        """Return the enrichment dict for the first IOC hit in ``record``, or ``None``."""
        snapshot = self._set
        for field, ip in _iter_ips(record):
            hit = snapshot.match_ip(ip)
            if hit is not None:
                return _hit(hit, field)
        for field, host in _iter_hosts(record):
            hit = snapshot.match_domain(host)
            if hit is not None:
                return _hit(hit, field)
        for field, digest in _iter_hashes(record):
            hit = snapshot.match_hash(digest)
            if hit is not None:
                return _hit(hit, field)
        return None

    # -- watching -------------------------------------------------------

    def start_watching(self) -> None:
        """Begin watching the IOC directory for changes (idempotent)."""
        if self._observer is not None or self._dir is None or not self._dir.is_dir():
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
        """Validate a created/modified file, then atomically swap the new set in."""
        parsed = self._read_and_validate(path)
        if parsed is None:
            return  # broken file — the live set is left untouched
        with self._lock:
            self._files[str(path)] = parsed
            self._rebuild_locked()
        _log.info("IOC file reloaded", extra={"path": str(path)})

    def _on_file_deleted(self, path: Path) -> None:
        """Drop a removed file's indicators."""
        with self._lock:
            if self._files.pop(str(path), None) is not None:
                self._rebuild_locked()
                _log.info("IOC file removed", extra={"path": str(path)})


class _ReloadHandler(FileSystemEventHandler):
    """Routes watchdog events for ``*.json`` files to the store."""

    def __init__(self, store: IndicatorStore) -> None:
        """Bind this handler to its ``store``."""
        self._store = store

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
        if not event.is_directory and str(event.src_path).endswith(".json"):
            self._store._on_file_deleted(Path(event.src_path))

    def _changed(self, event: FileSystemEvent, raw_path: object) -> None:
        """Forward a create/modify/move to the store if it is a JSON file."""
        if event.is_directory:
            return
        path = Path(str(raw_path))
        if path.suffix == ".json":
            self._store._on_file_changed(path)


class ThreatIntelEnricher:
    """Adds ``threat_intel`` context when a record observable matches a loaded IOC."""

    name = "threat_intel"

    def __init__(self, store: IndicatorStore) -> None:
        """Wrap a (usually already loaded) :class:`IndicatorStore`."""
        self._store = store

    @classmethod
    def from_settings(cls, settings: Settings) -> ThreatIntelEnricher:
        """Build from ``settings.enrich.ioc_dir`` (empty store if the dir is absent)."""
        store = IndicatorStore()
        ioc_dir = Path(settings.enrich.ioc_dir)
        if ioc_dir.is_dir():
            store.load_all(ioc_dir)
        else:
            _log.warning(
                "threat_intel: IOC directory %s not found; enricher active but empty",
                ioc_dir,
            )
        return cls(store)

    @property
    def store(self) -> IndicatorStore:
        """The underlying indicator store (for hot-reload wiring and introspection)."""
        return self._store

    def describe(self) -> dict[str, Any]:
        """Readiness summary for the /health endpoint."""
        counts = self._store.indicators.counts()
        total = sum(counts.values())
        return {"ready": total > 0, "detail": f"{total} indicators {counts}"}

    def start(self) -> None:
        """Start hot-reload watching of the IOC directory."""
        self._store.start_watching()

    def stop(self) -> None:
        """Stop hot-reload watching."""
        self._store.stop_watching()

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        """Return ``{"threat_intel": {...}}`` on the first IOC hit, else ``{}``."""
        hit = self._store.match(record)
        return {"threat_intel": hit} if hit is not None else {}


def _hit(indicator: Indicator, field: str) -> dict[str, Any]:
    """The enrichment payload for one indicator match."""
    return {
        "matched": True,
        "indicator": indicator.value,
        "ioc_type": indicator.ioc_type,
        "ioc_source": indicator.source,
        "confidence": indicator.confidence,
        "matched_on": field,
    }


def _iter_ips(record: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """Yield ``(field, ip)`` for the src and dst endpoint addresses."""
    for key in ("src_endpoint", "dst_endpoint"):
        endpoint = record.get(key)
        if isinstance(endpoint, dict) and isinstance(endpoint.get("ip"), str):
            yield f"{key}.ip", endpoint["ip"]


def _iter_hosts(record: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(dotted_field, hostname)`` for every hostname/domain-like value."""
    if isinstance(record, dict):
        for key, value in record.items():
            child = f"{path}.{key}" if path else key
            if key in _HOST_KEYS and isinstance(value, str) and value:
                yield child, value
            else:
                yield from _iter_hosts(value, child)
    elif isinstance(record, list):
        for index, item in enumerate(record):
            yield from _iter_hosts(item, f"{path}.{index}")


def _iter_hashes(record: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(dotted_field, digest)`` for every hash-like value, incl. fingerprint lists."""
    if isinstance(record, dict):
        for key, value in record.items():
            child = f"{path}.{key}" if path else key
            if key in _HASH_KEYS and isinstance(value, str) and value:
                yield child, value
            elif key in ("fingerprints", "hashes") and isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, dict) and isinstance(item.get("value"), str):
                        yield f"{child}.{index}.value", item["value"]
            else:
                yield from _iter_hashes(value, child)
    elif isinstance(record, list):
        for index, item in enumerate(record):
            yield from _iter_hashes(item, f"{path}.{index}")
