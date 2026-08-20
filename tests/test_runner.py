"""Scan orchestration: statuses, isolation, concurrency and cancellation."""

from __future__ import annotations

import asyncio

import pytest

from wosint.core.models import ModuleStatus, Severity
from wosint.core.process import ToolNotFound
from wosint.core.registry import register
from wosint.core.runner import ScanRunner
from wosint.core.settings import Settings
from wosint.core.targets import TargetType, parse_target
from wosint.modules.base import Availability, Module, ModuleOutput

TARGET = parse_target("example.com")


def make_module(name: str, behaviour, *, available: bool = True, types=None):
    """Build and register a module whose ``execute`` runs ``behaviour``."""

    class _Fake(Module):
        pass

    async def execute(self, target, ctx):
        return await behaviour(target, ctx)

    _Fake.name = name
    _Fake.title = name
    _Fake.kind = "api"
    _Fake.supported_types = frozenset(types or {TargetType.DOMAIN})
    _Fake.execute = execute
    if not available:
        _Fake.availability = lambda self, settings: Availability.missing("tool missing")
    _Fake.__abstractmethods__ = frozenset()
    register(_Fake)
    return _Fake


async def _one_finding(target, ctx):
    out = ModuleOutput(raw="raw text")
    out.add("dns", "A record", "1.2.3.4", severity=Severity.NOTABLE)
    return out


async def _nothing(target, ctx):
    return ModuleOutput(raw="")


async def _boom(target, ctx):
    raise RuntimeError("upstream exploded")


async def _slow(target, ctx):
    await asyncio.sleep(30)
    return ModuleOutput()


async def test_successful_module(isolated_registry, settings) -> None:
    make_module("good", _one_finding)
    scan = await ScanRunner(settings).run(TARGET)

    result = scan.results["good"]
    assert result.status is ModuleStatus.OK
    assert result.finding_count == 1
    assert result.raw == "raw text"
    assert not scan.is_running


async def test_module_with_no_findings_is_empty_not_error(isolated_registry, settings) -> None:
    make_module("quiet", _nothing)
    scan = await ScanRunner(settings).run(TARGET)
    assert scan.results["quiet"].status is ModuleStatus.EMPTY
    assert scan.results["quiet"].succeeded


async def test_one_failure_does_not_stop_the_scan(isolated_registry, settings) -> None:
    make_module("broken", _boom)
    make_module("good", _one_finding)

    scan = await ScanRunner(settings).run(TARGET)

    assert scan.results["broken"].status is ModuleStatus.ERROR
    assert "upstream exploded" in scan.results["broken"].error
    assert scan.results["good"].status is ModuleStatus.OK


async def test_timeout_is_reported_as_timeout(isolated_registry) -> None:
    make_module("slow", _slow)
    scan = await ScanRunner(Settings(module_timeout=0.2)).run(TARGET)
    assert scan.results["slow"].status is ModuleStatus.TIMEOUT


async def test_missing_tool_is_unavailable_not_error(isolated_registry, settings) -> None:
    make_module("needs-tool", _nothing, available=False)
    scan = await ScanRunner(settings).run(TARGET)

    result = scan.results["needs-tool"]
    assert result.status is ModuleStatus.UNAVAILABLE
    assert result.error == "tool missing"


async def test_tool_not_found_at_runtime_is_unavailable(isolated_registry, settings) -> None:
    async def missing(target, ctx):
        raise ToolNotFound("nmap")

    make_module("late-missing", missing)
    scan = await ScanRunner(settings).run(TARGET)
    assert scan.results["late-missing"].status is ModuleStatus.UNAVAILABLE


async def test_only_selected_modules_run(isolated_registry, settings) -> None:
    make_module("wanted", _one_finding)
    make_module("unwanted", _one_finding)

    scan = await ScanRunner(settings).run(TARGET, modules=["wanted"])
    assert set(scan.results) == {"wanted"}


async def test_modules_for_other_target_types_are_excluded(isolated_registry, settings) -> None:
    make_module("ip-only", _one_finding, types={TargetType.IPV4})
    scan = await ScanRunner(settings).run(TARGET)
    assert scan.results == {}
    assert not scan.is_running


async def test_progress_callback_sees_running_then_terminal(isolated_registry, settings) -> None:
    make_module("good", _one_finding)
    seen: list[ModuleStatus] = []

    await ScanRunner(settings).run(TARGET, on_update=lambda r: seen.append(r.status))
    assert seen == [ModuleStatus.RUNNING, ModuleStatus.OK]


async def test_broken_callback_cannot_break_a_scan(isolated_registry, settings) -> None:
    make_module("good", _one_finding)

    def explode(result):
        raise ValueError("bad listener")

    scan = await ScanRunner(settings).run(TARGET, on_update=explode)
    assert scan.results["good"].status is ModuleStatus.OK


async def test_concurrency_is_capped(isolated_registry) -> None:
    peak = 0
    live = 0

    async def tracked(target, ctx):
        nonlocal peak, live
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0.05)
        live -= 1
        return ModuleOutput()

    for index in range(8):
        make_module(f"m{index}", tracked)

    await ScanRunner(Settings(max_concurrency=3, module_timeout=5)).run(TARGET)
    assert peak <= 3


async def test_cancellation_marks_modules_cancelled(isolated_registry) -> None:
    make_module("slow", _slow)
    runner = ScanRunner(Settings(module_timeout=30))

    task = asyncio.create_task(runner.run(TARGET))
    await asyncio.sleep(0.1)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


async def test_findings_are_sorted_by_severity(isolated_registry, settings) -> None:
    async def mixed(target, ctx):
        out = ModuleOutput()
        out.add("a", "info", "low")
        out.add("a", "warn", "high", severity=Severity.WARNING)
        out.add("a", "notable", "mid", severity=Severity.NOTABLE)
        return out

    make_module("mixed", mixed)
    scan = await ScanRunner(settings).run(TARGET)
    assert [f.value for f in scan.findings] == ["high", "mid", "low"]


async def test_progress_counts(isolated_registry, settings) -> None:
    make_module("good", _one_finding)
    make_module("broken", _boom)
    scan = await ScanRunner(settings).run(TARGET)
    assert scan.progress == (2, 2)


async def test_scan_serialises_to_json_shape(isolated_registry, settings) -> None:
    make_module("good", _one_finding)
    payload = (await ScanRunner(settings).run(TARGET)).as_dict()

    assert payload["target"]["value"] == "example.com"
    assert payload["results"][0]["findings"][0]["value"] == "1.2.3.4"
    assert payload["results"][0]["status"] == "ok"
