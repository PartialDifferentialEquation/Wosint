"""IP geolocation and network ownership.

ip-api.com's free tier needs no key but only serves plain HTTP for anonymous
use; the module therefore treats a failure as ordinary rather than alarming and
never sends anything but the address itself.
"""

from __future__ import annotations

import json

from ..core.http import get_json
from ..core.models import Severity
from ..core.registry import register
from ..core.targets import Target, TargetType
from .base import ApiModule, ModuleOutput, RunContext

GEOIP_URL = "http://ip-api.com/json/{query}"

#: Requested fields, chosen to include the hosting/proxy flags.
FIELDS = ",".join(
    (
        "status",
        "message",
        "country",
        "regionName",
        "city",
        "zip",
        "lat",
        "lon",
        "timezone",
        "isp",
        "org",
        "as",
        "reverse",
        "proxy",
        "hosting",
        "query",
    )
)


@register
class GeoIpModule(ApiModule):
    """Country, network operator and hosting classification for an address."""

    name = "geoip"
    title = "IP geolocation"
    description = "Location, ISP, ASN and hosting/proxy flags for an IP address."
    source_url = "https://ip-api.com"
    supported_types = frozenset({TargetType.IPV4, TargetType.IPV6})

    async def execute(self, target: Target, ctx: RunContext) -> ModuleOutput:
        out = ModuleOutput()
        data = await get_json(
            ctx.client, GEOIP_URL.format(query=target.value), params={"fields": FIELDS}
        )
        out.raw = json.dumps(data, indent=2, sort_keys=True)

        if data.get("status") != "success":
            raise RuntimeError(str(data.get("message") or "geolocation lookup failed"))

        location = ", ".join(
            part for part in (data.get("city"), data.get("regionName"), data.get("country")) if part
        )
        out.add("network", "Location", location)
        out.add("network", "ISP", str(data.get("isp") or ""))
        out.add("network", "Organisation", str(data.get("org") or ""))
        out.add("network", "ASN", str(data.get("as") or ""))
        out.add("network", "Reverse DNS", str(data.get("reverse") or ""))
        out.add("network", "Timezone", str(data.get("timezone") or ""))
        if data.get("lat") is not None and data.get("lon") is not None:
            out.add("network", "Coordinates", f"{data['lat']}, {data['lon']}")

        if data.get("hosting"):
            out.add(
                "network",
                "Hosting",
                "datacentre or hosting provider",
                "not a residential address",
                Severity.NOTABLE,
            )
        if data.get("proxy"):
            out.add(
                "network",
                "Proxy",
                "known proxy, VPN or Tor exit",
                "traffic origin is obscured",
                Severity.WARNING,
            )
        return out
