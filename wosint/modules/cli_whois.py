"""The classic ``whois`` client.

RDAP covers most of the same ground in a structured way, but plenty of TLD
registries still publish detail only over port 43, so the local client stays
worth running when it is installed.
"""

from __future__ import annotations

from ..core.models import Severity
from ..core.process import CommandOutput
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import CliModule, ModuleOutput, RunContext

#: whois keys worth promoting to findings, mapped to display labels.
FIELDS = {
    "registrar": "Registrar",
    "registrant organization": "Registrant org",
    "registrant country": "Registrant country",
    "creation date": "Created",
    "created": "Created",
    "updated date": "Updated",
    "registry expiry date": "Expires",
    "expiry date": "Expires",
    "name server": "Nameserver",
    "netname": "Network name",
    "orgname": "Organisation",
    "org-name": "Organisation",
    "country": "Country",
    "cidr": "CIDR",
    "abuse-mailbox": "Abuse contact",
    "organisation": "Organisation",
}

#: Status values that mean the domain is locked, expiring or in dispute.
ALERT_STATUS = ("clienthold", "serverhold", "pendingdelete", "redemptionperiod")


@register
class WhoisModule(CliModule):
    """Registration details straight from the registry's whois server."""

    name = "whois"
    title = "whois"
    description = "Registration record from the local whois client."
    tool = "whois"
    install_hint = "apt install whois / brew install whois"
    supported_types = frozenset(
        {TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL, TargetType.IPV4, TargetType.IPV6}
    )

    def build_args(self, target: Target, ctx: RunContext) -> list[str]:
        query = target.value if target.is_ip else (target.domain or target.value)
        # "--" stops the query being parsed as an option even if it starts with
        # a hyphen, though parse_target already rules that out.
        return [self.tool, "--", query]

    def parse(self, output: CommandOutput, target: Target) -> ModuleOutput:
        out = ModuleOutput(raw=output.text)
        seen: set[tuple[str, str]] = set()

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith(("%", "#", ">>>")):
                continue
            key, sep, value = line.partition(":")
            if not sep:
                continue
            key, value = key.strip().lower(), value.strip()
            if not value:
                continue

            label = FIELDS.get(key)
            if label and (label, value) not in seen:
                seen.add((label, value))
                category = "dns" if label == "Nameserver" else "registration"
                out.add(category, label, value)
            elif key in ("domain status", "status"):
                flag = value.split()[0].lower()
                severity = (
                    Severity.WARNING if flag.replace("-", "") in ALERT_STATUS else Severity.INFO
                )
                if ("Status", value) not in seen:
                    seen.add(("Status", value))
                    out.add("registration", "Status", value, severity=severity)

        if _is_privacy_protected(output.stdout):
            out.add(
                "registration",
                "Privacy",
                "registrant details are redacted",
                "WHOIS privacy service or GDPR redaction in effect",
                Severity.NOTABLE,
            )
        return out


def _is_privacy_protected(body: str) -> bool:
    lowered = body.lower()
    return any(
        marker in lowered
        for marker in (
            "redacted for privacy",
            "privacy protect",
            "whoisguard",
            "domains by proxy",
            "data protected",
        )
    )
