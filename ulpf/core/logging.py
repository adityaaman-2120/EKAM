"""Structured JSON logging for ULPF.

``configure_logging`` installs a single stdout handler on the root logger that
emits one JSON object per line: ``ts`` (UTC ISO 8601), ``level``, ``logger``,
``message``, any ``exc``/``stack`` text, plus every extra field passed via the
standard ``logging`` ``extra=`` mechanism.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

# LogRecord attributes that are framework internals, not caller-supplied extras.
_RESERVED: frozenset[str] = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "taskName",
        "message",
        "asctime",
    }
)


class JsonFormatter(logging.Formatter):
    """Render a :class:`logging.LogRecord` as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize ``record`` to a compact JSON string."""
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        for key, val in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = val
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: int | str = "INFO") -> None:
    """Install the JSON stdout handler on the root logger at ``level``.

    Idempotent: existing handlers are removed so repeated calls (tests, reloads)
    do not stack duplicate output.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper() if isinstance(level, str) else level)
