"""Tests for :mod:`ulpf.parse.registry` and the :class:`ParseEngine` contract."""

from __future__ import annotations

from typing import Any

import pytest

from ulpf.parse.engines.base import ParseEngine
from ulpf.parse.registry import EngineRegistry
from ulpf.parse.registry import registry as module_registry


class _EchoEngine:
    name = "echo"

    def parse(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
        return {"text": text, "opt_count": len(options)}


class _KvEngine:
    name = "kv"

    def parse(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
        return dict(pair.split("=", 1) for pair in text.split() if "=" in pair)


def test_echo_engine_satisfies_the_protocol() -> None:
    assert isinstance(_EchoEngine(), ParseEngine)


def test_register_get_and_list_names() -> None:
    reg = EngineRegistry()
    reg.register(_EchoEngine())
    reg.register(_KvEngine())

    assert reg.list_names() == ["echo", "kv"]
    got = reg.get("kv")
    assert got.name == "kv"
    assert got.parse("a=1 b=2 noise", {}) == {"a": "1", "b": "2"}


def test_duplicate_registration_raises() -> None:
    reg = EngineRegistry()
    reg.register(_EchoEngine())
    with pytest.raises(ValueError):
        reg.register(_EchoEngine())


def test_get_unknown_engine_raises_key_error() -> None:
    reg = EngineRegistry()
    with pytest.raises(KeyError):
        reg.get("nope")


def test_engine_decorator_instantiates_and_registers() -> None:
    reg = EngineRegistry()

    @reg.engine
    class _DecoratedEngine:
        name = "decorated"

        def parse(self, text: str, options: dict[str, Any]) -> dict[str, Any]:
            return {"len": len(text)}

    assert reg.list_names() == ["decorated"]
    assert reg.get("decorated").parse("hello", {}) == {"len": 5}


def test_module_singleton_is_a_registry_and_load_is_idempotent() -> None:
    assert isinstance(module_registry, EngineRegistry)
    module_registry.load_engine_modules()
    names = set(module_registry.list_names())
    module_registry.load_engine_modules()  # second call must not raise or duplicate
    assert set(module_registry.list_names()) == names
    assert "json" in names  # the built-in JSON engine self-registered
