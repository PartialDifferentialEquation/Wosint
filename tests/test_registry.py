"""Module registration and target-based filtering."""

from __future__ import annotations

import pytest

from wosint.core.registry import all_modules, get_module, modules_for, register
from wosint.core.targets import TargetType, parse_target
from wosint.modules.base import Module, ModuleOutput


def _make_module(name: str, types: set[TargetType], kind: str = "api"):
    class _Fake(Module):
        pass

    _Fake.name = name
    _Fake.title = name.title()
    _Fake.kind = kind
    _Fake.supported_types = frozenset(types)
    _Fake.execute = lambda self, target, ctx: ModuleOutput()  # type: ignore[assignment]
    _Fake.__abstractmethods__ = frozenset()
    return _Fake


def test_registers_and_looks_up(isolated_registry) -> None:
    register(_make_module("alpha", {TargetType.DOMAIN}))
    assert get_module("alpha").name == "alpha"
    assert [m.name for m in all_modules()] == ["alpha"]


def test_duplicate_names_are_rejected(isolated_registry) -> None:
    register(_make_module("alpha", {TargetType.DOMAIN}))
    with pytest.raises(ValueError, match="duplicate"):
        register(_make_module("alpha", {TargetType.DOMAIN}))


def test_filters_by_target_type(isolated_registry) -> None:
    register(_make_module("domain-only", {TargetType.DOMAIN}))
    register(_make_module("ip-only", {TargetType.IPV4}))

    assert [m.name for m in modules_for(parse_target("example.com"))] == ["domain-only"]
    assert [m.name for m in modules_for(parse_target("1.2.3.4"))] == ["ip-only"]


def test_name_restriction_ignores_unknown_names(isolated_registry) -> None:
    """A stale saved selection must not break a scan."""
    register(_make_module("alpha", {TargetType.DOMAIN}))
    register(_make_module("beta", {TargetType.DOMAIN}))

    selected = modules_for(parse_target("example.com"), names=["alpha", "removed-module"])
    assert [m.name for m in selected] == ["alpha"]


def test_ordering_is_stable_by_kind_then_title(isolated_registry) -> None:
    register(_make_module("zeta", {TargetType.DOMAIN}, kind="api"))
    register(_make_module("alpha", {TargetType.DOMAIN}, kind="cli"))
    register(_make_module("beta", {TargetType.DOMAIN}, kind="api"))
    assert [m.name for m in all_modules()] == ["beta", "zeta", "alpha"]


def test_real_catalogue_is_populated() -> None:
    """The shipped modules register themselves on import."""
    names = {m.name for m in all_modules()}
    assert {"dns", "rdap", "crtsh", "whois", "sherlock"} <= names
