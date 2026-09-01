"""Exception hierarchy for ULPF.

Every failure raised inside the framework derives from :class:`UlpfError` and
may carry a structured ``detail`` mapping for logging and dead-letter records.
"""

from __future__ import annotations


class UlpfError(Exception):
    """Base class for all ULPF errors.

    Args:
        message: Human-readable summary.
        detail: Optional structured context (source id, offset, raw snippet...).
    """

    def __init__(self, message: str, detail: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail: dict[str, object] = detail or {}

    def __str__(self) -> str:
        """Render the message, appending detail keys when present."""
        if not self.detail:
            return self.message
        return f"{self.message} ({self.detail})"


class IngestError(UlpfError):
    """A listener or intake stage failed to accept an event."""


class SniffError(UlpfError):
    """Format detection could not classify a raw event."""


class ParseError(UlpfError):
    """A parse engine failed to extract source-specific attributes."""


class MappingError(UlpfError):
    """Normalization into the OCSF taxonomy failed."""


class ValidationError(UlpfError):
    """A normalized record failed schema or invariant validation."""


class IntegrityError(UlpfError):
    """A hash, Merkle proof, or ledger check did not verify."""
