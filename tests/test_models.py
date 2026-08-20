"""Data model behaviour."""

from __future__ import annotations

import time

from wosint.core.models import Finding, ModuleResult, ModuleStatus, Scan, Severity
from wosint.core.targets import parse_target
from wosint.modules.base import ModuleOutput


def test_severity_ranks_are_ordered() -> None:
    assert Severity.INFO.rank < Severity.NOTABLE.rank < Severity.WARNING.rank


def test_terminal_statuses() -> None:
    assert not ModuleStatus.PENDING.is_terminal
    assert not ModuleStatus.RUNNING.is_terminal
    for status in (
        ModuleStatus.OK,
        ModuleStatus.EMPTY,
        ModuleStatus.ERROR,
        ModuleStatus.TIMEOUT,
        ModuleStatus.UNAVAILABLE,
        ModuleStatus.CANCELLED,
    ):
        assert status.is_terminal


def test_empty_counts_as_success_but_error_does_not() -> None:
    assert ModuleResult("m", "M", "api", status=ModuleStatus.EMPTY).succeeded
    assert ModuleResult("m", "M", "api", status=ModuleStatus.OK).succeeded
    assert not ModuleResult("m", "M", "api", status=ModuleStatus.ERROR).succeeded


def test_module_output_ignores_blank_values() -> None:
    output = ModuleOutput()
    output.add("dns", "A record", "")
    output.add("dns", "A record", "   ")
    output.add("dns", "A record", "1.2.3.4")

    assert [f.value for f in output.findings] == ["1.2.3.4"]


def test_module_output_strips_whitespace() -> None:
    output = ModuleOutput()
    output.add("dns", "A record", "  1.2.3.4  ", "  TTL 300s  ")

    assert output.findings[0].value == "1.2.3.4"
    assert output.findings[0].detail == "TTL 300s"


def test_scan_progress_counts_only_terminal_modules() -> None:
    scan = Scan(target=parse_target("example.com"))
    scan.results = {
        "a": ModuleResult("a", "A", "api", status=ModuleStatus.OK),
        "b": ModuleResult("b", "B", "api", status=ModuleStatus.RUNNING),
        "c": ModuleResult("c", "C", "api", status=ModuleStatus.ERROR),
    }
    assert scan.progress == (2, 3)


def test_scan_is_running_until_finished() -> None:
    scan = Scan(target=parse_target("example.com"))
    assert scan.is_running

    scan.finished_at = time.time()
    assert not scan.is_running


def test_scan_findings_are_sorted_by_severity() -> None:
    scan = Scan(target=parse_target("example.com"))
    scan.results = {
        "a": ModuleResult("a", "A", "api", findings=[Finding("x", "low", "1")]),
        "b": ModuleResult(
            "b", "B", "api", findings=[Finding("x", "high", "2", severity=Severity.WARNING)]
        ),
    }
    assert [f.label for f in scan.findings] == ["high", "low"]


def test_scan_serialisation_round_trips_the_essentials() -> None:
    scan = Scan(target=parse_target("bob@example.com"))
    scan.results = {
        "a": ModuleResult(
            "a",
            "A",
            "api",
            status=ModuleStatus.OK,
            findings=[Finding("dns", "A", "1.2.3.4")],
            raw="raw",
        )
    }
    scan.finished_at = scan.started_at + 1.5

    payload = scan.as_dict()

    assert payload["target"] == {
        "value": "bob@example.com",
        "type": "email",
        "raw": "bob@example.com",
    }
    assert payload["duration_ms"] == 1500
    assert payload["results"][0]["raw"] == "raw"
    assert payload["results"][0]["findings"][0]["severity"] == "info"


def test_scan_ids_are_distinct() -> None:
    target = parse_target("example.com")
    assert Scan(target=target).id != Scan(target=target).id
