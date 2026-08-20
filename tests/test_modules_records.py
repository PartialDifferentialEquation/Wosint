"""Public-records modules: filings, dockets, registries and Wikidata."""

from __future__ import annotations

import httpx
import respx

from wosint.core.models import Severity
from wosint.core.registry import get_module
from wosint.core.settings import Settings
from wosint.core.targets import parse_target


def values(output, label: str) -> list[str]:
    return [f.value for f in output.findings if f.label == label]


def first(output, label: str):
    return next(f for f in output.findings if f.label == label)


# -- SEC EDGAR ---------------------------------------------------------------

SEC_RESPONSE = {
    "hits": {
        "total": {"value": 47},
        "hits": [
            {
                "_id": "0001045810-22-000163:x.htm",
                "_source": {
                    "display_names": ["NVIDIA CORP  (NVDA)  (CIK 0001045810)"],
                    "ciks": ["0001045810"],
                    "form": "8-K",
                    "file_date": "2022-11-16",
                },
            }
        ],
    }
}


def test_sec_requires_a_contact_address() -> None:
    """The SEC's access policy asks callers to identify themselves."""
    availability = get_module("sec").availability(Settings())

    assert not availability.ok
    assert "WOSINT_CONTACT_EMAIL" in availability.reason


def test_sec_is_available_once_a_contact_is_configured() -> None:
    assert get_module("sec").availability(Settings(contact_email="me@example.com")).ok


@respx.mock
async def test_sec_reports_filings_and_filers(ctx) -> None:
    ctx.settings.contact_email = "me@example.com"
    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(200, json=SEC_RESPONSE)
    )
    output = await get_module("sec").execute(parse_target("Ada Lovelace"), ctx)

    assert values(output, "SEC filings") == ["47 filings mention this name"]
    assert values(output, "Named in filing by") == ["NVIDIA CORP  (NVDA)  (CIK 0001045810)"]
    assert "8-K filed 2022-11-16" in first(output, "Named in filing by").detail


@respx.mock
async def test_sec_sends_the_configured_contact(ctx) -> None:
    ctx.settings.contact_email = "me@example.com"
    route = respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(200, json=SEC_RESPONSE)
    )
    await get_module("sec").execute(parse_target("Ada Lovelace"), ctx)

    assert "me@example.com" in route.calls[0].request.headers["user-agent"]


@respx.mock
async def test_a_name_match_in_a_filing_is_only_an_inference(ctx) -> None:
    """A full-text hit on a name is not proof it is the same person."""
    ctx.settings.contact_email = "me@example.com"
    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(200, json=SEC_RESPONSE)
    )
    output = await get_module("sec").execute(parse_target("Ada Lovelace"), ctx)

    assert first(output, "Named in filing by").inferred


@respx.mock
async def test_no_filings_is_an_empty_result_not_an_error(ctx) -> None:
    ctx.settings.contact_email = "me@example.com"
    respx.get("https://efts.sec.gov/LATEST/search-index").mock(
        return_value=httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
    )
    output = await get_module("sec").execute(parse_target("Ada Lovelace"), ctx)

    assert output.findings == []


# -- CourtListener -----------------------------------------------------------

DOCKET_RESPONSE = {
    "count": 27,
    "results": [
        {
            "caseName": "Neural AI, LLC v. Meta Platforms, Inc.",
            "court": "District Court, W.D. Texas",
            "docketNumber": "7:26-cv-00322",
            "dateFiled": "2026-08-18",
            "docket_absolute_url": "/docket/74665715/neural-ai-llc-v-meta/",
        }
    ],
}


@respx.mock
async def test_courtlistener_reports_dockets(ctx) -> None:
    respx.get("https://www.courtlistener.com/api/rest/v4/search/").mock(
        return_value=httpx.Response(200, json=DOCKET_RESPONSE)
    )
    output = await get_module("courtlistener").execute(parse_target("Ada Lovelace"), ctx)

    assert values(output, "Docket") == ["Neural AI, LLC v. Meta Platforms, Inc."]
    assert "7:26-cv-00322" in first(output, "Docket").detail
    assert values(output, "Docket record") == [
        "https://www.courtlistener.com/docket/74665715/neural-ai-llc-v-meta/"
    ]


@respx.mock
async def test_docket_matches_are_inferred(ctx) -> None:
    """A docket names parties, counsel and judges; a hit is not identification."""
    respx.get("https://www.courtlistener.com/api/rest/v4/search/").mock(
        return_value=httpx.Response(200, json=DOCKET_RESPONSE)
    )
    output = await get_module("courtlistener").execute(parse_target("Ada Lovelace"), ctx)

    assert first(output, "Docket").inferred


@respx.mock
async def test_courtlistener_works_without_a_token_and_uses_one_if_set(ctx) -> None:
    route = respx.get("https://www.courtlistener.com/api/rest/v4/search/").mock(
        return_value=httpx.Response(200, json={"count": 0, "results": []})
    )
    await get_module("courtlistener").execute(parse_target("Ada Lovelace"), ctx)
    assert "authorization" not in route.calls[0].request.headers

    ctx.settings.api_keys["courtlistener"] = "tok"
    await get_module("courtlistener").execute(parse_target("Ada Lovelace"), ctx)
    assert route.calls[1].request.headers["authorization"] == "Token tok"


# -- OpenSanctions and OpenCorporates ----------------------------------------


def test_key_gated_records_modules_report_what_they_need() -> None:
    for name in ("opensanctions", "opencorporates"):
        availability = get_module(name).availability(Settings())
        assert not availability.ok
        assert f"WOSINT_KEY_{name.upper()}" in availability.reason


@respx.mock
async def test_opensanctions_flags_a_listed_person(ctx) -> None:
    ctx.settings.api_keys["opensanctions"] = "k"
    respx.get("https://api.opensanctions.org/search/default").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "caption": "Some Person",
                        "schema": "Person",
                        "datasets": ["eu_fsf"],
                        "properties": {"country": ["ru"], "birthDate": ["1952-10-07"]},
                    }
                ]
            },
        )
    )
    output = await get_module("opensanctions").execute(parse_target("Some Person"), ctx)

    listed = first(output, "Listed person")
    assert listed.severity is Severity.WARNING
    assert listed.inferred
    assert values(output, "Date of birth") == ["1952-10-07"]


@respx.mock
async def test_opensanctions_says_so_when_there_is_no_match(ctx) -> None:
    ctx.settings.api_keys["opensanctions"] = "k"
    respx.get("https://api.opensanctions.org/search/default").mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    output = await get_module("opensanctions").execute(parse_target("Ada Lovelace"), ctx)

    assert values(output, "Sanctions") == ["no match"]


@respx.mock
async def test_opencorporates_reports_officerships(ctx) -> None:
    ctx.settings.api_keys["opencorporates"] = "k"
    respx.get("https://api.opencorporates.com/v0.4/officers/search").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": {
                    "officers": [
                        {
                            "officer": {
                                "company": {"name": "Acme Ltd"},
                                "position": "director",
                                "jurisdiction_code": "gb",
                                "start_date": "2019-04-01",
                                "opencorporates_url": "https://opencorporates.com/officers/1",
                            }
                        }
                    ]
                }
            },
        )
    )
    output = await get_module("opencorporates").execute(parse_target("Jane Doe"), ctx)

    assert values(output, "Officer of") == ["Acme Ltd"]
    assert "director" in first(output, "Officer of").detail


# -- Wikidata ----------------------------------------------------------------

SEARCH_ONE = {"search": [{"id": "Q7259", "label": "Ada Lovelace", "description": "mathematician"}]}
SEARCH_TWO = {
    "search": [
        {"id": "Q7259", "label": "Ada Lovelace", "description": "mathematician"},
        {"id": "Q999", "label": "Ada Lovelace", "description": "a ship"},
    ]
}


def wikidata_item(claims: dict) -> dict:
    return {"entities": {"Q7259": {"labels": {"en": {"value": "Ada Lovelace"}}, "claims": claims}}}


def string_claim(value: str) -> list[dict]:
    return [{"mainsnak": {"datavalue": {"value": value}}}]


def time_claim(value: str) -> list[dict]:
    return [{"mainsnak": {"datavalue": {"value": {"time": value}}}}]


def item_claim(item_id: str) -> list[dict]:
    return [{"mainsnak": {"datavalue": {"value": {"id": item_id}}}}]


@respx.mock
async def test_wikidata_reads_biographical_claims(ctx) -> None:
    respx.get("https://www.wikidata.org/w/api.php").mock(
        side_effect=[
            httpx.Response(200, json=SEARCH_ONE),
            httpx.Response(
                200,
                json=wikidata_item(
                    {"P569": time_claim("+1815-12-10T00:00:00Z"), "P106": item_claim("Q170790")}
                ),
            ),
            httpx.Response(
                200,
                json={"entities": {"Q170790": {"labels": {"en": {"value": "mathematician"}}}}},
            ),
        ]
    )
    output = await get_module("wikidata").execute(parse_target("Ada Lovelace"), ctx)

    assert values(output, "Date of birth") == ["1815-12-10"]
    # Referenced items are resolved to readable labels, not left as "Q170790".
    assert values(output, "Occupation") == ["mathematician"]


@respx.mock
async def test_wikidata_turns_self_declared_handles_into_accounts(ctx) -> None:
    respx.get("https://www.wikidata.org/w/api.php").mock(
        side_effect=[
            httpx.Response(200, json=SEARCH_ONE),
            httpx.Response(200, json=wikidata_item({"P2037": string_claim("janedoe")})),
        ]
    )
    output = await get_module("wikidata").execute(parse_target("Ada Lovelace"), ctx)

    assert "https://github.com/janedoe" in values(output, "GitHub")
    account = next(f for f in output.findings if f.category == "account")
    assert account.severity is Severity.NOTABLE


@respx.mock
async def test_wikidata_says_when_a_name_is_shared(ctx) -> None:
    """Picking the most popular match silently would be the wrong person."""
    respx.get("https://www.wikidata.org/w/api.php").mock(
        side_effect=[
            httpx.Response(200, json=SEARCH_TWO),
            httpx.Response(200, json=wikidata_item({"P569": time_claim("+1815-12-10T00:00:00Z")})),
        ]
    )
    output = await get_module("wikidata").execute(parse_target("Ada Lovelace"), ctx)

    assert values(output, "Name is shared") == ["2 Wikidata items match this name"]
    assert first(output, "Date of birth").inferred


@respx.mock
async def test_wikidata_identifies_itself_per_the_robot_policy(ctx) -> None:
    route = respx.get("https://www.wikidata.org/w/api.php").mock(
        return_value=httpx.Response(200, json={"search": []})
    )
    await get_module("wikidata").execute(parse_target("Ada Lovelace"), ctx)

    assert "Wosint" in route.calls[0].request.headers["user-agent"]


@respx.mock
async def test_wikidata_handles_an_unknown_name(ctx) -> None:
    respx.get("https://www.wikidata.org/w/api.php").mock(
        return_value=httpx.Response(200, json={"search": []})
    )
    output = await get_module("wikidata").execute(parse_target("Nobody Here"), ctx)

    assert output.findings == []


# -- records links (offline) -------------------------------------------------


async def test_records_links_cover_registries_for_a_person(ctx) -> None:
    output = await get_module("records").execute(parse_target("Ada Lovelace"), ctx)
    labels = {f.label for f in output.findings}

    assert {"Company officers", "SEC filings", "US court dockets", "Patents"} <= labels
    assert all("Ada+Lovelace" in f.value or f.label == "Searching for" for f in output.findings)


async def test_records_links_use_the_registrable_name_for_a_domain(ctx) -> None:
    output = await get_module("records").execute(parse_target("acmecorp.com"), ctx)

    assert values(output, "Searching for") == ["acmecorp"]


async def test_records_links_send_nothing(ctx) -> None:
    with respx.mock(assert_all_mocked=True):
        await get_module("records").execute(parse_target("Ada Lovelace"), ctx)
