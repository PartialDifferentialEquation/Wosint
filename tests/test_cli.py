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


# -- reopening a profile -----------------------------------------------------


def write_profile(tmp_path, **overrides):
    """A small exported profile on disk, for the reopening tests."""
    from wosint.core.correlate import Investigation
    from wosint.core.models import Finding, ModuleResult, ModuleStatus, Scan
    from wosint.core.targets import parse_target

    scan = Scan(target=parse_target("bob@example.com"))
    scan.results["gravatar"] = ModuleResult(
        module="gravatar",
        title="Gravatar",
        kind="api",
        status=ModuleStatus.OK,
        findings=[
            Finding("profile", "Full name", "Jane Doe"),
            Finding("account", "Github", "https://github.com/janedoe"),
            Finding("profile", "Employer", "Acme Corp", "guessed", inferred=True),
        ],
    )
    scan.finished_at = scan.started_at
    investigation = Investigation()
    investigation.add_scan(scan)

    payload = investigation.as_dict()
    payload.update(overrides)
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_a_saved_profile_prints_without_qt(tmp_path) -> None:
    """The engine's picture has to be readable headlessly, or it lives in the GUI."""
    from wosint.cli import show_profile

    stream = io.StringIO()
    assert show_profile(str(write_profile(tmp_path)), as_json=False, stream=stream) == 0

    output = stream.getvalue()
    assert "bob@example.com" in output
    assert "Jane Doe" in output
    assert "[follow next]" in output
    assert "janedoe" in output


def test_a_printed_profile_marks_what_rests_on_a_guess(tmp_path) -> None:
    from wosint.cli import show_profile

    stream = io.StringIO()
    show_profile(str(write_profile(tmp_path)), as_json=False, stream=stream)

    line = next(line for line in stream.getvalue().splitlines() if "Acme Corp" in line)
    assert "inferred, unconfirmed" in line
    assert "25%" in line


def test_a_saved_profile_reprints_as_json(tmp_path) -> None:
    from wosint.cli import show_profile

    path = write_profile(tmp_path)
    stream = io.StringIO()
    assert show_profile(str(path), as_json=True, stream=stream) == 0

    assert json.loads(stream.getvalue()) == json.loads(path.read_text(encoding="utf-8"))


def test_a_file_that_is_not_a_profile_fails_with_a_reason(tmp_path, capsys) -> None:
    from wosint.cli import show_profile

    path = tmp_path / "notes.json"
    path.write_text('{"notes": "nothing to see"}', encoding="utf-8")

    assert show_profile(str(path), as_json=False, stream=io.StringIO()) == 1
    assert "entities" in capsys.readouterr().err


def test_a_missing_profile_fails_rather_than_raising(tmp_path, capsys) -> None:
    from wosint.cli import show_profile

    assert show_profile(str(tmp_path / "gone.json"), as_json=False, stream=io.StringIO()) == 1
    assert "error:" in capsys.readouterr().err


def test_main_dispatches_to_the_profile_command(tmp_path, capsys) -> None:
    assert main(["profile", str(write_profile(tmp_path))]) == 0
    assert "Jane Doe" in capsys.readouterr().out


def test_a_binary_file_fails_rather_than_raising(tmp_path, capsys) -> None:
    """Picking a photo by mistake is a bad file, not a traceback."""
    from wosint.cli import show_profile

    path = tmp_path / "photo.json"
    path.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00")

    assert show_profile(str(path), as_json=False, stream=io.StringIO()) == 1
    assert "error:" in capsys.readouterr().err
