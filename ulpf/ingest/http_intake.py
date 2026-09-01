"""HTTP intake — a FastAPI app served on its own port, apart from the main API.

The management/query API (``ulpf.api``) and this ingest surface have very
different traffic, auth, and blast-radius profiles, so they run as separate
ASGI apps on separate ports (``settings.ingest.http_port``, default 8081). This
module exposes:

* ``POST /ingest/raw``  — text body, one event per line; ``?source_id=`` optional.
* ``POST /ingest/json`` — a JSON array or NDJSON; each element/line is one event.
* ``POST /ingest/hec``  — Splunk HTTP Event Collector shape
  (``{"event": ..., "sourcetype": ...}``, one or many objects) for drop-in use.

Every accepted item becomes a :class:`~ulpf.core.models.RawEvent` with
``transport="http"`` via :func:`~ulpf.integrity.hashing.make_raw_event` (hashed
before anything else), is handed to the injected ``on_event`` callback, and its
UUID is returned. All three endpoints answer ``{"accepted": n, "event_uids":
[...]}``. Bodies larger than ``settings.ingest.http_max_body_bytes`` are refused
with ``413``.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request, status
from pydantic import BaseModel

from ulpf.config.settings import Settings
from ulpf.core.errors import IngestError
from ulpf.core.metrics import BYTES_RECEIVED, EVENTS_RECEIVED
from ulpf.core.models import RawEvent
from ulpf.integrity.hashing import make_raw_event

OnEvent = Callable[[RawEvent], Awaitable[None]]

_SOURCE_RAW = "http-raw"
_SOURCE_JSON = "http-json"
_SOURCE_HEC = "http-hec"


class IngestResult(BaseModel):
    """Response body for every intake endpoint."""

    accepted: int
    event_uids: list[str]


def _peer(request: Request) -> str | None:
    """Best-effort client IP for the request."""
    return request.client.host if request.client else None


async def _read_capped_body(request: Request, max_bytes: int) -> bytes:
    """Return the request body, rejecting anything over ``max_bytes`` with 413."""
    too_large = HTTPException(413, detail=f"body exceeds {max_bytes} bytes")
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > max_bytes:
        raise too_large
    body = await request.body()
    if len(body) > max_bytes:
        raise too_large
    return body


def _canonical_json(value: object) -> bytes:
    """Deterministic compact JSON encoding used when no framed bytes exist."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()


def _split_lines(body: bytes) -> list[bytes]:
    """Split on LF, drop a trailing CR, and skip blank/whitespace-only lines."""
    lines: list[bytes] = []
    for chunk in body.split(b"\n"):
        line = chunk[:-1] if chunk.endswith(b"\r") else chunk
        if line.strip():
            lines.append(line)
    return lines


def _parse_json_events(body: bytes) -> list[bytes]:
    """Yield one raw-bytes payload per element of a JSON array or NDJSON body."""
    stripped = body.lstrip()
    if not stripped:
        return []
    if stripped[:1] == b"[":
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise HTTPException(422, detail=f"invalid JSON array: {exc}") from exc
        if not isinstance(parsed, list):
            raise HTTPException(422, detail="expected a JSON array")
        return [_canonical_json(item) for item in parsed]
    out: list[bytes] = []
    for lineno, chunk in enumerate(body.split(b"\n"), start=1):
        line = chunk[:-1] if chunk.endswith(b"\r") else chunk
        if not line.strip():
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            raise HTTPException(422, detail=f"invalid JSON on line {lineno}: {exc}") from exc
        out.append(line)
    return out


def _parse_hec_events(body: bytes, default_source_id: str) -> list[tuple[bytes, str]]:
    """Parse one or more concatenated Splunk HEC objects into (raw, source_id) pairs."""
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    decoder = json.JSONDecoder()
    out: list[tuple[bytes, str]] = []
    idx, length = 0, len(text)
    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        try:
            obj, idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError as exc:
            raise HTTPException(422, detail=f"invalid HEC payload at offset {idx}: {exc}") from exc
        if not isinstance(obj, dict) or "event" not in obj:
            raise HTTPException(422, detail="each HEC record must be an object with an 'event'")
        event = obj["event"]
        raw = event.encode("utf-8") if isinstance(event, str) else _canonical_json(event)
        out.append((raw, str(obj.get("sourcetype") or default_source_id)))
    return out


def build_intake_router(settings: Settings, on_event: OnEvent) -> APIRouter:
    """Build the ``/ingest`` router, wiring each accepted event to ``on_event``."""
    router = APIRouter(prefix="/ingest", tags=["intake"])
    max_bytes = settings.ingest.http_max_body_bytes

    async def emit(items: list[tuple[bytes, str]], request: Request) -> IngestResult:
        """Turn (raw, source_id) pairs into RawEvents, dispatch, collect UUIDs."""
        peer = _peer(request)
        uids: list[str] = []
        for raw, source_id in items:
            EVENTS_RECEIVED.labels(transport="http").inc()
            BYTES_RECEIVED.labels(transport="http").inc(len(raw))
            event = make_raw_event(raw, source_id=source_id, transport="http", peer=peer)
            try:
                await on_event(event)
            except IngestError as exc:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail={"accepted": len(uids), "error": str(exc)},
                ) from exc
            uids.append(event.event_uid)
        return IngestResult(accepted=len(uids), event_uids=uids)

    @router.post("/raw", response_model=IngestResult)
    async def ingest_raw(
        request: Request, source_id: str | None = Query(default=None)
    ) -> IngestResult:
        body = await _read_capped_body(request, max_bytes)
        sid = source_id or _SOURCE_RAW
        return await emit([(line, sid) for line in _split_lines(body)], request)

    @router.post("/json", response_model=IngestResult)
    async def ingest_json(
        request: Request, source_id: str | None = Query(default=None)
    ) -> IngestResult:
        body = await _read_capped_body(request, max_bytes)
        sid = source_id or _SOURCE_JSON
        return await emit([(raw, sid) for raw in _parse_json_events(body)], request)

    @router.post("/hec", response_model=IngestResult)
    async def ingest_hec(
        request: Request, source_id: str | None = Query(default=None)
    ) -> IngestResult:
        body = await _read_capped_body(request, max_bytes)
        return await emit(_parse_hec_events(body, source_id or _SOURCE_HEC), request)

    return router


def create_intake_app(settings: Settings, on_event: OnEvent) -> FastAPI:
    """Create the standalone HTTP-intake ASGI app (serve on ``ingest.http_port``)."""
    app = FastAPI(title="ULPF HTTP Intake", version="0.1.0")
    app.include_router(build_intake_router(settings, on_event))
    return app
