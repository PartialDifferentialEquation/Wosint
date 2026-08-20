"""Settings loading, environment overrides and persistence."""

from __future__ import annotations

import json

from wosint.core.settings import Settings, config_path


def test_defaults_are_sane() -> None:
    settings = Settings()
    assert settings.module_timeout > 0
    assert settings.max_concurrency >= 1
    assert "wosint" in settings.user_agent.lower()


def test_reads_a_config_file(tmp_path, monkeypatch) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"module_timeout": 12.5, "max_concurrency": 2}))
    monkeypatch.delenv("WOSINT_MAX_CONCURRENCY", raising=False)

    settings = Settings.load(path)

    assert settings.module_timeout == 12.5
    assert settings.max_concurrency == 2


def test_unknown_keys_in_the_file_are_ignored(tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"module_timeout": 9.0, "not_a_setting": True}))

    assert Settings.load(path).module_timeout == 9.0


def test_a_broken_config_file_falls_back_to_defaults(tmp_path) -> None:
    """A stray comma must not stop the application from starting."""
    path = tmp_path / "config.json"
    path.write_text("{ this is not json")

    assert Settings.load(path).module_timeout == Settings().module_timeout


def test_a_missing_config_file_is_fine(tmp_path) -> None:
    assert Settings.load(tmp_path / "absent.json").max_concurrency >= 1


def test_environment_overrides_the_file(tmp_path, monkeypatch) -> None:
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"module_timeout": 12.5}))
    monkeypatch.setenv("WOSINT_MODULE_TIMEOUT", "3")

    assert Settings.load(path).module_timeout == 3.0


def test_invalid_environment_values_are_ignored(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WOSINT_MAX_CONCURRENCY", "not-a-number")
    assert Settings.load(tmp_path / "absent.json").max_concurrency == Settings().max_concurrency


def test_api_keys_come_from_the_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WOSINT_KEY_SHODAN", "secret-value")

    settings = Settings.load(tmp_path / "absent.json")

    assert settings.api_key("shodan") == "secret-value"
    assert settings.api_key("unset-module") is None


def test_disabled_modules_from_the_environment(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WOSINT_DISABLED_MODULES", "dns, wayback ,")

    assert Settings.load(tmp_path / "absent.json").disabled_modules == ["dns", "wayback"]


def test_save_and_reload(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("WOSINT_MODULE_TIMEOUT", raising=False)
    path = tmp_path / "nested" / "config.json"

    Settings(module_timeout=21.0).save(path)

    assert path.exists()
    assert Settings.load(path).module_timeout == 21.0


def test_config_path_honours_the_override(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("WOSINT_CONFIG", str(tmp_path / "custom.json"))
    assert config_path() == tmp_path / "custom.json"
