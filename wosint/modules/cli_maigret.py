"""Username search with ``maigret``.

maigret covers considerably more sites than sherlock and, where a site exposes
one, pulls the profile's name, bio and linked accounts out too.
"""

from __future__ import annotations

import json
from typing import ClassVar

from ..core.models import Severity
from ..core.process import CommandOutput
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import CliModule, ModuleOutput, RunContext

#: Profile fields maigret extracts that are worth promoting to findings.
PROFILE_FIELDS = {
    "fullname": "Name",
    "name": "Name",
    "location": "Location",
    "country": "Country",
    "gender": "Gender",
    "bio": "Bio",
    "email": "Email",
    "url": "Profile URL",
}


@register
class MaigretModule(CliModule):
    """Accounts and profile details for a username across many sites."""

    name = "maigret"
    title = "maigret (username search)"
    description = "Wide username search that also extracts profile details."
    tool = "maigret"
    install_hint = "pipx install maigret"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.USERNAME, TargetType.EMAIL})

    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        username = (
            target.value.split("@", 1)[0] if target.type is TargetType.EMAIL else target.value
        )
        # "-J ndjson" puts one JSON object per line on stdout, which is far more
        # reliable to parse than the decorated console output.
        return [
            self.tool,
            "--no-color",
            "--no-progressbar",
            "--timeout",
            "10",
            "-J",
            "ndjson",
            "--",
            username,
        ]

    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        out = ModuleOutput(raw=output.text)
        seen_details: set[tuple[str, str]] = set()

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict) or record.get("status") != "claimed":
                continue

            site = str(record.get("site") or record.get("sitename") or "site")
            out.add(
                "account",
                site,
                str(record.get("url_user") or record.get("url") or ""),
                "account exists",
                Severity.NOTABLE,
            )

            ids = record.get("ids")
            if isinstance(ids, dict):
                for key, label in PROFILE_FIELDS.items():
                    value = ids.get(key)
                    if not isinstance(value, str) or not value.strip():
                        continue
                    if (label, value) in seen_details:
                        continue
                    seen_details.add((label, value))
                    out.add("profile", label, value, f"from the {site} profile", Severity.NOTABLE)

        if out.findings:
            accounts = sum(1 for f in out.findings if f.category == "account")
            out.add("account", "Accounts found", str(accounts))
        return out
