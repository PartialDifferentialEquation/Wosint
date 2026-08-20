"""DNS resolution over DNS-over-HTTPS.

Using DoH rather than the system resolver means the DNS module works
identically on a machine with no ``dig`` installed, and the queries do not leak
to whatever resolver the host happens to be configured with.
"""

from __future__ import annotations

import ipaddress

from ..core.http import get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

DOH_URL = "https://dns.google/resolve"

#: Record types queried for a domain, in the order they are displayed.
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME")

#: TXT prefixes that say something about the domain's mail posture.
POLICY_PREFIXES = ("v=spf1", "v=dmarc1", "google-site-verification", "v=dkim1")


@register
class DnsModule(ApiModule):
    """Forward and reverse DNS records resolved over HTTPS."""

    name = "dns"
    title = "DNS records"
    description = "A/AAAA/MX/NS/TXT/SOA lookups (and PTR for IPs) via DNS-over-HTTPS."
    source_url = "https://dns.google"
    supported_types = frozenset(
        {TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL, TargetType.IPV4, TargetType.IPV6}
    )

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        lines: list[str] = []

        if target.is_ip:
            await self._reverse(target, ctx, out, lines)
        else:
            domain = target.domain
            if not domain:
                return out
            for record_type in RECORD_TYPES:
                await self._lookup(domain, record_type, ctx, out, lines)
            self._check_mail_posture(out)

        out.raw = "\n".join(lines) or "no DNS records returned"
        return out

    async def _lookup(
        self,
        domain: str,
        record_type: str,
        ctx: RunContext,
        out: ModuleOutput,
        lines: list[str],
    ) -> None:
        data = await get_json(ctx.client, DOH_URL, params={"name": domain, "type": record_type})
        for answer in data.get("Answer") or []:
            value = str(answer.get("data") or "").strip()
            if not value:
                continue
            lines.append(f"{domain}\t{answer.get('TTL', '')}\t{record_type}\t{value}")
            severity = Severity.INFO
            detail = f"TTL {answer['TTL']}s" if answer.get("TTL") else ""
            if record_type == "TXT" and value.strip('"').lower().startswith(POLICY_PREFIXES):
                severity = Severity.NOTABLE
            out.add("dns", f"{record_type} record", value.strip('"'), detail, severity)

    async def _reverse(
        self, target: Target, ctx: RunContext, out: ModuleOutput, lines: list[str]
    ) -> None:
        # PTR records live under in-addr.arpa / ip6.arpa, not under the
        # address itself -- querying the literal returns nothing at all.
        pointer = ipaddress.ip_address(target.value).reverse_pointer
        data = await get_json(ctx.client, DOH_URL, params={"name": pointer, "type": "PTR"})
        for answer in data.get("Answer") or []:
            value = str(answer.get("data") or "").strip().rstrip(".")
            lines.append(f"{pointer}\tPTR\t{value}")
            out.add("dns", "PTR record", value, "reverse DNS")

    def _check_mail_posture(self, out: ModuleOutput) -> None:
        """Flag a domain that publishes MX records but no SPF policy.

        A domain that receives mail but does not declare which hosts may send
        as it is a spoofing risk worth pointing out.
        """
        txt = [f.value.lower() for f in out.findings if f.label == "TXT record"]
        has_mx = any(f.label == "MX record" for f in out.findings)
        if has_mx and not any(v.startswith("v=spf1") for v in txt):
            out.add(
                "dns",
                "Mail policy",
                "no SPF record published",
                "domain accepts mail but does not declare authorised senders",
                Severity.WARNING,
            )
