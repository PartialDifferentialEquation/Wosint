"""Registration data (RDAP) for domains and IP addresses.

RDAP is the structured, JSON successor to WHOIS and needs no API key, which
makes it the most dependable registration lookup available to Wosint.
"""

from __future__ import annotations

import json
from typing import Any

from ..core.http import get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

DOMAIN_RDAP = "https://rdap.org/domain/{query}"
IP_RDAP = "https://rdap.org/ip/{query}"

#: RDAP event names worth surfacing, mapped to display labels.
EVENT_LABELS = {
    "registration": "Registered",
    "expiration": "Expires",
    "last changed": "Last changed",
    "transfer": "Transferred",
}


@register
class RdapModule(ApiModule):
    """Registrar, registration dates, nameservers and status flags."""

    name = "rdap"
    title = "RDAP registration"
    description = "Registration records for domains and IP ranges via rdap.org."
    source_url = "https://rdap.org"
    supported_types = frozenset(
        {TargetType.DOMAIN, TargetType.EMAIL, TargetType.URL, TargetType.IPV4, TargetType.IPV6}
    )

    def _query(self, target: Target) -> tuple[str, str] | None:
        if target.is_ip:
            return IP_RDAP.format(query=target.value), "ip"
        domain = target.domain
        return (DOMAIN_RDAP.format(query=domain), "domain") if domain else None

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        query = self._query(target)
        out = ModuleOutput()
        if query is None:
            return out

        url, mode = query
        data = await get_json(ctx.client, url)
        out.raw = json.dumps(data, indent=2, sort_keys=True)[:200_000]

        if mode == "ip":
            self._parse_ip(data, out)
        else:
            self._parse_domain(data, out)
        return out

    def _parse_domain(self, data: dict[str, Any], out: ModuleOutput) -> None:
        out.add("registration", "Domain", str(data.get("ldhName") or ""))

        for entity in data.get("entities") or []:
            roles = [str(r) for r in entity.get("roles") or []]
            name = _entity_name(entity)
            if not name:
                continue
            for role in roles:
                out.add("registration", role.title(), name)

        for event in data.get("events") or []:
            label = EVENT_LABELS.get(str(event.get("eventAction", "")).lower())
            if label:
                out.add("registration", label, str(event.get("eventDate") or ""))

        for nameserver in data.get("nameservers") or []:
            out.add("dns", "Nameserver", str(nameserver.get("ldhName") or ""))

        for status in data.get("status") or []:
            severity = (
                Severity.WARNING
                if any(flag in str(status).lower() for flag in ("hold", "pending delete"))
                else Severity.INFO
            )
            out.add("registration", "Status", str(status), severity=severity)

    def _parse_ip(self, data: dict[str, Any], out: ModuleOutput) -> None:
        out.add("network", "Network name", str(data.get("name") or ""))
        out.add("network", "Handle", str(data.get("handle") or ""))
        out.add("network", "Country", str(data.get("country") or ""))
        out.add("network", "IP version", str(data.get("ipVersion") or ""))
        start, end = data.get("startAddress"), data.get("endAddress")
        if start and end:
            out.add("network", "Range", f"{start} - {end}")
        for entity in data.get("entities") or []:
            name = _entity_name(entity)
            for role in entity.get("roles") or []:
                out.add("network", str(role).title(), name)
        for remark in data.get("remarks") or []:
            for line in remark.get("description") or []:
                out.add("network", "Remark", str(line))


def _entity_name(entity: dict[str, Any]) -> str:
    """Pull a display name out of an RDAP entity's jCard.

    jCard is an awkward nested-array format; the entries we want are
    ``[name, params, type, value]`` triples inside ``vcardArray[1]``.
    """
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
        fields = {}
        for entry in vcard[1]:
            if isinstance(entry, list) and len(entry) >= 4 and isinstance(entry[0], str):
                fields.setdefault(entry[0], entry[3])
        for key in ("fn", "org", "email"):
            value = fields.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    handle = entity.get("handle")
    return str(handle) if handle else ""
