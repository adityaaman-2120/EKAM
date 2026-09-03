"""The decode boundary: raw bytes -> working text, with a leading BOM removed.

A file written with a byte-order mark (Windows PowerShell 5.1's ``-Encoding
UTF8`` adds one, as do many editors) puts a U+FEFF *before* the first real
character. That silently breaks format detection — ``"﻿{"`` no longer
starts with ``{`` — and every engine that anchors on the first byte.

:func:`decode_raw` strips a leading UTF-8 or UTF-16 (LE/BE) BOM from the decoded
**working copy** only. ``RawEvent.raw`` and ``raw_hash`` are never touched: the
BOM is part of the original evidence and stays in the bronze store byte for
byte. The returned flag lets callers record that a BOM was seen and removed.
"""

from __future__ import annotations

import codecs

# Checked longest-first so a UTF-8 BOM is never mistaken for a shorter prefix.
_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF8, "utf-8"),  # EF BB BF
    (codecs.BOM_UTF16_LE, "utf-16-le"),  # FF FE
    (codecs.BOM_UTF16_BE, "utf-16-be"),  # FE FF
)


def decode_raw(raw: bytes) -> tuple[str, bool]:
    """Decode ``raw`` to text for detection/parsing, stripping any leading BOM.

    Args:
        raw: The original event bytes, exactly as received.

    Returns:
        ``(text, bom_stripped)`` — ``text`` is the decoded string with any
        leading BOM removed; ``bom_stripped`` is ``True`` when one was present.
        Decoding uses ``errors="replace"`` so arbitrary bytes never raise.
    """
    for bom, encoding in _BOMS:
        if raw.startswith(bom):
            return raw[len(bom) :].decode(encoding, errors="replace"), True
    return raw.decode("utf-8", errors="replace"), False


def strip_bom_bytes(raw: bytes) -> bytes:
    """Return ``raw`` without a leading UTF-8/UTF-16 BOM, re-encoded as UTF-8.

    For the syslog-envelope parser, which works on bytes: a UTF-16 payload is
    transcoded to UTF-8 so downstream byte offsets are consistent with
    :func:`decode_raw`. Callers pass this only when a BOM was actually stripped.
    """
    text, stripped = decode_raw(raw)
    return text.encode("utf-8") if stripped else raw
