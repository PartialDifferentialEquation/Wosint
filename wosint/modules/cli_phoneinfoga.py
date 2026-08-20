"""Phone number reconnaissance with ``phoneinfoga``.

phoneinfoga adds what a local number-metadata lookup cannot: results from the
online scanners it drives.
"""

from __future__ import annotations

import re
from typing import ClassVar

from ..core.models import Severity
from ..core.process import CommandOutput
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import CliModule, ModuleOutput, RunContext

#: phoneinfoga prints "Key: value" pairs under each scanner's heading.
FIELD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z /]+):\s*(.+?)\s*$")

#: Fields worth surfacing, mapped to display labels.
FIELDS = {
    "country": "Country",
    "carrier": "Carrier",
    "local time": "Local time",
    "location": "Location",
    "line type": "Line type",
    "raw local": "National format",
    "international": "E.164",
}


@register
class PhoneInfogaModule(CliModule):
    """Scanner results for a phone number."""

    name = "phoneinfoga"
    title = "phoneinfoga"
    description = "Runs phoneinfoga's online scanners against a number."
    tool = "phoneinfoga"
    install_hint = "https://sundowndev.github.io/phoneinfoga/install/"
    supported_types: ClassVar[frozenset] = frozenset({TargetType.PHONE})
    default_enabled = False

    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        return [self.tool, "scan", "-n", target.value]

    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        out = ModuleOutput(raw=output.text)
        seen: set[tuple[str, str]] = set()

        for line in output.stdout.splitlines():
            match = FIELD_RE.match(line)
            if not match:
                continue
            key, value = match.group(1).strip().lower(), match.group(2).strip()
            label = FIELDS.get(key)
            if not label or not value or (label, value) in seen:
                continue
            seen.add((label, value))
            out.add("phone", label, value)

        for url in re.findall(r"https?://\S+", output.stdout):
            if (("Footprint"), url) not in seen:
                seen.add(("Footprint", url))
                out.add("search", "Footprint link", url, "suggested by phoneinfoga", Severity.INFO)
        return out
