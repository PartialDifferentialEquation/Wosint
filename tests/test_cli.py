"""The headless command line interface."""

from __future__ import annotations

import io
import json

from wosint.__main__ import build_parser, main
from wosint.cli import list_modules, run_scan
from wosint.core.models import Severity
from wosint.core.registry import register
from wosint.core.settings import Settings
from wosint.core.targets import TargetType
from wosint.modules.base import Module, ModuleOutput


def register_fake(name: str = "fake") -> None:
    class _Fake(Module):
        pass

    async def execute(self, target, ctx):
        output = ModuleOutput(raw="raw output")
        output.add("dns", "A record", "1.2.3.4")
        output.add("dns", "Mail policy", "no SPF record", severity=Severity.WARNING)
        return output

    _Fake.name = name
    _Fake.title = "Fake module"
    _Fake.kind = "api"
    _Fake.supported_types = frozenset({TargetType.DOMAIN})
    _Fake.execute = execute
    _Fake.__abstractmethods__ = frozenset()
    register(_Fake)


def test_text_report_groups_by_category(isolated_registry, settings: Settings) -> None:
    register_fake()
    stream = io.StringIO()

    code = run_scan("example.com", modules=None, as_json=False, stream=stream, settings=settings)
    report = stream.getvalue()

    assert code == 0
    assert "example.com (Domain)" in report
    assert "[dns]" in report
    assert "1.2.3.4" in report
    assert "no SPF record" in report
    assert "2 findings · 1/1 modules" in report


def test_json_output_is_machine_readable(isolated_registry, settings: Settings) -> None:
    register_fake()
    stream = io.StringIO()

    run_scan("example.com", modules=None, as_json=True, stream=stream, settings=settings)
    payload = json.loads(stream.getvalue())

    assert payload["target"]["value"] == "example.com"
    assert payload["results"][0]["module"] == "fake"
    assert len(payload["results"][0]["findings"]) == 2


def test_module_selection_is_honoured(isolated_registry, settings: Settings) -> None:
    register_fake("wanted")
    register_fake("unwanted")
    stream = io.StringIO()

    run_scan("example.com", modules=["wanted"], as_json=True, stream=stream, settings=settings)
    payload = json.loads(stream.getvalue())

    assert [r["module"] for r in payload["results"]] == ["wanted"]


def test_invalid_target_exits_nonzero(isolated_registry, settings: Settings) -> None:
    stream = io.StringIO()
    code = run_scan("not a target!", modules=None, as_json=False, stream=stream, settings=settings)
    assert code == 1


def test_no_applicable_modules_exits_nonzero(isolated_registry, settings: Settings) -> None:
    """A scan that could run nothing is a failure, not a silent success."""
    stream = io.StringIO()
    code = run_scan("example.com", modules=None, as_json=False, stream=stream, settings=settings)
    assert code == 1


def test_list_modules_shows_availability() -> None:
    stream = io.StringIO()
    assert list_modules(stream) == 0
    listing = stream.getvalue()

    assert "dns" in listing and "rdap" in listing
    assert "unavailable:" in listing  # the CLI tools are not installed in CI


def test_parser_defaults_to_the_gui() -> None:
    assert build_parser().parse_args([]).command is None


def test_parser_reads_repeated_module_flags() -> None:
    args = build_parser().parse_args(["scan", "example.com", "-m", "dns", "-m", "rdap"])
    assert args.modules == ["dns", "rdap"]
    assert args.target == "example.com"


def test_main_dispatches_to_modules_listing(capsys) -> None:
    assert main(["modules"]) == 0
    assert "rdap" in capsys.readouterr().out


def test_main_scan_applies_timeout_override(isolated_registry, monkeypatch, capsys) -> None:
    register_fake()
    captured = {}

    def fake_run_scan(target, *, modules, as_json, stream, settings):
        captured["timeout"] = settings.module_timeout
        return 0

    monkeypatch.setattr("wosint.cli.run_scan", fake_run_scan)
    assert main(["scan", "example.com", "--timeout", "7"]) == 0
    assert captured["timeout"] == 7.0
