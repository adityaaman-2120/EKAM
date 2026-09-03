"""Tests for :mod:`ulpf.enrich.base` — the enricher contract."""

from __future__ import annotations

from typing import Any

from ulpf.core.errors import UlpfError
from ulpf.enrich.base import Enricher, EnricherError


class _Conforming:
    name = "conforming"

    def enrich(self, record: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True}


class _MissingMethod:
    name = "broken"


def test_enricher_protocol_is_runtime_checkable() -> None:
    assert isinstance(_Conforming(), Enricher)
    assert not isinstance(_MissingMethod(), Enricher)
    assert not isinstance(object(), Enricher)


def test_enricher_error_is_a_ulpf_error() -> None:
    err = EnricherError("no reference data loaded", detail={"enricher": "geo"})
    assert isinstance(err, UlpfError)
    assert err.detail == {"enricher": "geo"}
