"""Tests for :mod:`ulpf.parse.decode` — the BOM-stripping decode boundary."""

from __future__ import annotations

import codecs

import pytest

from ulpf.parse.decode import decode_raw, strip_bom_bytes

_PLAIN = '{"a":1}'


def test_no_bom_is_plain_utf8_decode() -> None:
    text, stripped = decode_raw(_PLAIN.encode("utf-8"))
    assert text == _PLAIN
    assert stripped is False


def test_utf8_bom_is_stripped_from_the_text_only() -> None:
    raw = codecs.BOM_UTF8 + _PLAIN.encode("utf-8")
    text, stripped = decode_raw(raw)
    assert text == _PLAIN  # no leading U+FEFF
    assert text[0] == "{"
    assert stripped is True


@pytest.mark.parametrize(
    "bom_const, encoding",
    [(codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be")],
)
def test_utf16_boms_are_decoded_and_stripped(bom_const: bytes, encoding: str) -> None:
    raw = bom_const + _PLAIN.encode(encoding)
    text, stripped = decode_raw(raw)
    assert text == _PLAIN
    assert stripped is True


def test_invalid_bytes_do_not_raise() -> None:
    text, stripped = decode_raw(b"\x81\x82 not utf-8")
    assert isinstance(text, str)  # errors="replace"
    assert stripped is False


def test_strip_bom_bytes_returns_utf8_without_bom() -> None:
    assert strip_bom_bytes(_PLAIN.encode("utf-8")) == _PLAIN.encode("utf-8")
    assert strip_bom_bytes(codecs.BOM_UTF8 + _PLAIN.encode("utf-8")) == _PLAIN.encode("utf-8")
    assert strip_bom_bytes(codecs.BOM_UTF16_LE + _PLAIN.encode("utf-16-le")) == _PLAIN.encode(
        "utf-8"
    )
