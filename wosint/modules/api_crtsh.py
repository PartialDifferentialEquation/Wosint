"""Subdomain discovery from Certificate Transparency logs.

Every publicly trusted TLS certificate is logged, so crt.sh is an effective way
to enumerate a domain's subdomains without sending a single packet to the
target itself.
"""

from __future__ import annotations

from ..core.http import get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

CRTSH_URL = "https://crt.sh/"

#: Certificates covering this many hosts are usually shared infrastructure.
BULK_CERT_THRESHOLD = 40


@register
class CrtShModule(ApiModule):
    """Subdomains and issuers seen in Certificate Transparency logs."""

    name = "crtsh"
    title = "Certificate Transparency (crt.sh)"
    description = "Subdomains and certificate issuers from public CT logs."
    source_url = "https://crt.sh"
    supported_types = frozenset({TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL})

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        domain = target.domain
        if not domain:
            return out

        entries = await get_json(
            ctx.client, CRTSH_URL, params={"q": f"%.{domain}", "output": "json"}
        )
        if not isinstance(entries, list):
            return out

        hosts: dict[str, str] = {}
        issuers: dict[str, int] = {}

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            issuer = str(entry.get("issuer_name") or "").strip()
            if issuer:
                issuers[issuer] = issuers.get(issuer, 0) + 1
            seen = str(entry.get("name_value") or "")
            for host in seen.splitlines():
                host = host.strip().lower().lstrip("*.")
                if host.endswith(domain) and host != domain:
                    hosts.setdefault(host, str(entry.get("not_after") or ""))

        out.raw = "\n".join(sorted(hosts)) or "no subdomains found in CT logs"

        for host in sorted(hosts):
            severity = (
                Severity.NOTABLE
                if any(
                    marker in host
                    for marker in ("dev", "staging", "test", "internal", "vpn", "admin")
                )
                else Severity.INFO
            )
            detail = f"certificate valid until {hosts[host]}" if hosts[host] else ""
            out.add("certificate", "Subdomain", host, detail, severity)

        for issuer, count in sorted(issuers.items(), key=lambda kv: -kv[1])[:5]:
            out.add("certificate", "Issuer", _issuer_name(issuer), f"{count} certificates")

        if len(hosts) >= BULK_CERT_THRESHOLD:
            out.add(
                "certificate",
                "Attack surface",
                f"{len(hosts)} distinct hostnames in CT logs",
                "large certificate footprint",
                Severity.NOTABLE,
            )
        return out


def _issuer_name(issuer: str) -> str:
    """Reduce an X.500 issuer DN to its common or organisation name."""
    for key in ("CN=", "O="):
        for part in issuer.split(","):
            part = part.strip()
            if part.startswith(key):
                return part[len(key) :]
    return issuer
