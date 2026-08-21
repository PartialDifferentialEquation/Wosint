"""Runtime configuration.

Settings come from a JSON file in the user's config directory, with
environment variables taking precedence so a scan can be run in CI or a
container without touching the file.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_USER_AGENT = "wosint/0.1 (+https://github.com/PartialDifferentialEquation/Wosint)"


def config_path() -> Path:
    """Location of the settings file, honouring ``WOSINT_CONFIG``."""
    override = os.environ.get("WOSINT_CONFIG")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base).expanduser() / "wosint" / "config.json"


@dataclass(slots=True)
class Settings:
    """Everything the engine needs to know that is not part of a target.

    Attributes:
        module_timeout: Seconds a single module may run before being killed.
        max_concurrency: How many modules may run at once.
        http_timeout: Per-request timeout for API modules.
        user_agent: Sent with every outbound HTTP request.
        phone_region: Two-letter region used to interpret phone numbers typed
            without a country code. Empty means such numbers stay ambiguous
            rather than being guessed at.
        contact_email: Address sent to public-records services whose access
            policy requires callers to identify themselves.
        vision_model: Overrides the model the image-analysis module uses. Empty
            means the module's own default.
        api_keys: Keyed by module name, for modules that need credentials.
        disabled_modules: Module names never offered or run.
    """

    module_timeout: float = 45.0
    max_concurrency: int = 6
    http_timeout: float = 20.0
    user_agent: str = DEFAULT_USER_AGENT
    phone_region: str = ""
    contact_email: str = ""
    vision_model: str = ""
    api_keys: dict[str, str] = field(default_factory=dict)
    disabled_modules: list[str] = field(default_factory=list)
    #: Names of keys that came from the environment rather than the config file.
    #: Never persisted: writing a secret to disk because it happened to be
    #: exported would be a surprising thing for a save to do.
    env_keys: set[str] = field(default_factory=set, repr=False, compare=False)

    @classmethod
    def load(cls, path: Path | None = None) -> Settings:
        """Read settings from disk, then apply environment overrides.

        A malformed or unreadable config file is not fatal -- defaults are used
        instead, because failing to start the whole application over a stray
        comma would be worse than ignoring the file.
        """
        path = path or config_path()
        data: dict = {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            data = {}

        known = set(cls.__slots__) - {"env_keys"}
        settings = cls(**{k: v for k, v in data.items() if k in known})
        settings._apply_env()
        return settings

    def _apply_env(self) -> None:
        for name, cast in (
            ("module_timeout", float),
            ("max_concurrency", int),
            ("http_timeout", float),
            ("user_agent", str),
            ("phone_region", str),
            ("contact_email", str),
            ("vision_model", str),
        ):
            raw = os.environ.get(f"WOSINT_{name.upper()}")
            if raw:
                try:
                    setattr(self, name, cast(raw))
                except ValueError:
                    pass

        # API keys are read per module, e.g. WOSINT_KEY_SHODAN=... for the
        # module registered as "shodan".
        prefix = "WOSINT_KEY_"
        for key, value in os.environ.items():
            if key.startswith(prefix) and value:
                name = key[len(prefix) :].lower()
                self.api_keys[name] = value
                self.env_keys.add(name)

        disabled = os.environ.get("WOSINT_DISABLED_MODULES")
        if disabled:
            self.disabled_modules = [m.strip() for m in disabled.split(",") if m.strip()]

    def api_key(self, module: str) -> str | None:
        return self.api_keys.get(module) or None

    def save(self, path: Path | None = None) -> Path:
        """Write settings to disk, creating the config directory if needed.

        Keys that arrived from the environment are left out: they belong to the
        shell that exported them, and copying them into a file on disk would
        turn a transient secret into a permanent one behind the user's back.

        The file is written owner-only, because it holds API keys.
        """
        path = path or config_path()
        path.parent.mkdir(parents=True, exist_ok=True)

        data = asdict(self)
        data.pop("env_keys", None)
        data["api_keys"] = {
            name: value for name, value in self.api_keys.items() if name not in self.env_keys
        }

        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            # Not every filesystem supports it; the settings are still written.
            pass
        return path

    def is_from_environment(self, module: str) -> bool:
        """Whether this module's key came from the environment."""
        return module in self.env_keys

    def set_api_key(self, module: str, key: str) -> None:
        """Store or clear a key for ``module``.

        Refuses to touch a key the environment supplied: the file would be
        ignored on the next load anyway, so silently accepting the edit would
        be a lie.
        """
        if module in self.env_keys:
            raise ValueError(f"{module}'s key comes from the environment and cannot be edited here")
        key = key.strip()
        if key:
            self.api_keys[module] = key
        else:
            self.api_keys.pop(module, None)
