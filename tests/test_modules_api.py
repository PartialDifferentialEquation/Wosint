"""API module parsing, against mocked HTTP responses."""

from __future__ import annotations

import httpx
import pytest
import respx

from wosint.core.http import HttpError
from wosint.core.models import Severity
from wosint.core.registry import get_module
from wosint.core.targets import parse_target


def values(output, label: str) -> list[str]:
    return [f.value for f in output.findings if f.label == label]


# -- RDAP --------------------------------------------------------------------

RDAP_DOMAIN = {
    "ldhName": "EXAMPLE.COM",
    "status": ["client transfer prohibited", "client hold"],
    "events": [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        {"eventAction": "reregistration", "eventDate": "2020-01-01T00:00:00Z"},
    ],
    "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "NS2.EXAMPLE.COM"}],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [["version", {}, "text", "4.0"], ["fn", {}, "text", "Acme Registrar"]],
            ],
        }
    ],
}


@respx.mock
async def test_rdap_domain(ctx) -> None:
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=RDAP_DOMAIN)
    )
    output = await get_module("rdap").execute(parse_target("example.com"), ctx)

    assert values(output, "Registrar") == ["Acme Registrar"]
    assert values(output, "Registered") == ["1995-08-14T04:00:00Z"]
    assert values(output, "Expires") == ["2027-08-13T04:00:00Z"]
    assert sorted(values(output, "Nameserver")) == ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]
    # Unrecognised events are ignored rather than shown with a blank label.
    assert "2020-01-01T00:00:00Z" not in [f.value for f in output.findings]


@respx.mock
async def test_rdap_flags_hold_status_as_warning(ctx) -> None:
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=RDAP_DOMAIN)
    )
    output = await get_module("rdap").execute(parse_target("example.com"), ctx)

    by_value = {f.value: f.severity for f in output.findings}
    assert by_value["client hold"] is Severity.WARNING
    assert by_value["client transfer prohibited"] is Severity.INFO


@respx.mock
async def test_rdap_uses_the_ip_endpoint_for_addresses(ctx) -> None:
    route = respx.get("https://rdap.org/ip/1.2.3.4").mock(
        return_value=httpx.Response(
            200,
            json={
                "name": "TESTNET",
                "handle": "NET-1-2-3-0",
                "country": "AU",
                "startAddress": "1.2.3.0",
                "endAddress": "1.2.3.255",
            },
        )
    )
    output = await get_module("rdap").execute(parse_target("1.2.3.4"), ctx)

    assert route.called
    assert values(output, "Network name") == ["TESTNET"]
    assert values(output, "Range") == ["1.2.3.0 - 1.2.3.255"]


@respx.mock
async def test_rdap_uses_the_domain_of_an_email(ctx) -> None:
    route = respx.get("https://rdap.org/domain/example.com").mock(
        return_value=httpx.Response(200, json=RDAP_DOMAIN)
    )
    await get_module("rdap").execute(parse_target("bob@example.com"), ctx)
    assert route.called


@respx.mock
async def test_http_error_is_raised_for_the_runner(ctx) -> None:
    respx.get("https://rdap.org/domain/example.com").mock(return_value=httpx.Response(503))
    with pytest.raises(HttpError):
        await get_module("rdap").execute(parse_target("example.com"), ctx)


# -- DNS ---------------------------------------------------------------------


def _doh(record_type: str, *answers: str):
    return httpx.Response(
        200,
        json={"Answer": [{"data": a, "TTL": 300, "type": 1} for a in answers]},
    )


@respx.mock
async def test_dns_collects_each_record_type(ctx) -> None:
    respx.get("https://dns.google/resolve", params={"type": "A"}).mock(
        return_value=_doh("A", "1.2.3.4")
    )
    respx.get("https://dns.google/resolve", params={"type": "MX"}).mock(
        return_value=_doh("MX", "10 mail.example.com.")
    )
    respx.get("https://dns.google/resolve", params={"type": "TXT"}).mock(
        return_value=_doh("TXT", '"v=spf1 -all"')
    )
    respx.get("https://dns.google/resolve").mock(return_value=httpx.Response(200, json={}))

    output = await get_module("dns").execute(parse_target("example.com"), ctx)

    assert values(output, "A record") == ["1.2.3.4"]
    assert values(output, "MX record") == ["10 mail.example.com."]
    assert values(output, "TXT record") == ["v=spf1 -all"]


@respx.mock
async def test_dns_flags_mx_without_spf(ctx) -> None:
    respx.get("https://dns.google/resolve", params={"type": "MX"}).mock(
        return_value=_doh("MX", "10 mail.example.com.")
    )
    respx.get("https://dns.google/resolve").mock(return_value=httpx.Response(200, json={}))

    output = await get_module("dns").execute(parse_target("example.com"), ctx)

    spf = [f for f in output.findings if f.label == "Mail policy"]
    assert spf and spf[0].severity is Severity.WARNING


@respx.mock
async def test_dns_reverse_lookup_uses_arpa_name(ctx) -> None:
    """PTR queries must use the reverse-pointer name, not the raw address."""
    route = respx.get(
        "https://dns.google/resolve", params={"name": "4.3.2.1.in-addr.arpa", "type": "PTR"}
    ).mock(return_value=_doh("PTR", "host.example.com."))

    output = await get_module("dns").execute(parse_target("1.2.3.4"), ctx)

    assert route.called
    assert values(output, "PTR record") == ["host.example.com"]


# -- crt.sh ------------------------------------------------------------------


@respx.mock
async def test_crtsh_extracts_and_dedupes_subdomains(ctx) -> None:
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "name_value": "www.example.com\n*.example.com",
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                    "not_after": "2027-01-01",
                },
                {
                    "name_value": "www.example.com",
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                    "not_after": "2027-01-01",
                },
                {
                    "name_value": "dev.example.com",
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                    "not_after": "2027-01-01",
                },
                {
                    "name_value": "example.com",
                    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
                    "not_after": "2027-01-01",
                },
            ],
        )
    )
    output = await get_module("crtsh").execute(parse_target("example.com"), ctx)

    subdomains = values(output, "Subdomain")
    # The apex is not a subdomain, wildcards are unwrapped, duplicates collapse.
    assert subdomains == ["dev.example.com", "www.example.com"]
    assert values(output, "Issuer") == ["R3"]


@respx.mock
async def test_crtsh_flags_interesting_hostnames(ctx) -> None:
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[{"name_value": "staging.example.com\nwww.example.com", "issuer_name": "CN=X"}],
        )
    )
    output = await get_module("crtsh").execute(parse_target("example.com"), ctx)

    severities = {f.value: f.severity for f in output.findings if f.label == "Subdomain"}
    assert severities["staging.example.com"] is Severity.NOTABLE
    assert severities["www.example.com"] is Severity.INFO


# -- HackerTarget ------------------------------------------------------------


@respx.mock
async def test_hackertarget_parses_host_search(ctx) -> None:
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="www.example.com,1.2.3.4\nmail.example.com,1.2.3.5\n")
    )
    output = await get_module("hackertarget").execute(parse_target("example.com"), ctx)

    assert values(output, "Host") == ["www.example.com", "mail.example.com"]


@respx.mock
async def test_hackertarget_reports_quota_exhaustion(ctx) -> None:
    respx.get("https://api.hackertarget.com/hostsearch/").mock(
        return_value=httpx.Response(200, text="API count exceeded - Increase Quota with Membership")
    )
    output = await get_module("hackertarget").execute(parse_target("example.com"), ctx)

    assert values(output, "Rate limit") == ["HackerTarget daily quota exceeded"]


@respx.mock
async def test_hackertarget_caps_shared_hosting_results(ctx) -> None:
    """A shared address must not bury every other finding."""
    body = "\n".join(f"host{i}.example.com" for i in range(500))
    respx.get("https://api.hackertarget.com/reverseiplookup/").mock(
        return_value=httpx.Response(200, text=body)
    )
    output = await get_module("hackertarget").execute(parse_target("1.2.3.4"), ctx)

    assert len(values(output, "Hosted domain")) == 200
    assert values(output, "Shared hosting") == ["500 domains resolve to 1.2.3.4"]
    assert "host499.example.com" in output.raw


# -- GeoIP -------------------------------------------------------------------


@respx.mock
async def test_geoip_reports_location_and_flags(ctx) -> None:
    respx.get("http://ip-api.com/json/1.2.3.4").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "success",
                "city": "Sydney",
                "regionName": "New South Wales",
                "country": "Australia",
                "isp": "Example ISP",
                "hosting": True,
                "proxy": True,
                "lat": -33.8,
                "lon": 151.2,
            },
        )
    )
    output = await get_module("geoip").execute(parse_target("1.2.3.4"), ctx)

    assert values(output, "Location") == ["Sydney, New South Wales, Australia"]
    assert values(output, "Coordinates") == ["-33.8, 151.2"]
    by_label = {f.label: f.severity for f in output.findings}
    assert by_label["Hosting"] is Severity.NOTABLE
    assert by_label["Proxy"] is Severity.WARNING


@respx.mock
async def test_geoip_failure_status_raises(ctx) -> None:
    respx.get("http://ip-api.com/json/1.2.3.4").mock(
        return_value=httpx.Response(200, json={"status": "fail", "message": "reserved range"})
    )
    with pytest.raises(RuntimeError, match="reserved range"):
        await get_module("geoip").execute(parse_target("1.2.3.4"), ctx)


# -- Wayback -----------------------------------------------------------------


@respx.mock
async def test_wayback_summarises_coverage_and_flags_files(ctx) -> None:
    respx.get("https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(
            200,
            json=[
                ["timestamp", "original", "statuscode"],
                ["20100102030405", "http://example.com/", "200"],
                ["20240506070809", "http://example.com/backup.sql", "200"],
            ],
        )
    )
    output = await get_module("wayback").execute(parse_target("example.com"), ctx)

    assert values(output, "Coverage") == ["2010-01-02 to 2024-05-06"]
    flagged = {f.value: f.severity for f in output.findings if f.label == "Archived URL"}
    assert flagged["http://example.com/backup.sql"] is Severity.NOTABLE
    assert flagged["http://example.com/"] is Severity.INFO


@respx.mock
async def test_wayback_handles_empty_index(ctx) -> None:
    respx.get("https://web.archive.org/cdx/search/cdx").mock(
        return_value=httpx.Response(200, json=[])
    )
    output = await get_module("wayback").execute(parse_target("example.com"), ctx)
    assert output.findings == []
