"""Modules that work on people: emails, usernames, phone numbers and names."""

from __future__ import annotations

import httpx
import pytest
import respx

from wosint.core.http import HttpError
from wosint.core.models import Severity
from wosint.core.registry import get_module
from wosint.core.settings import Settings
from wosint.core.targets import parse_target
from wosint.modules.api_gravatar import gravatar_hash
from wosint.modules.base import RunContext


def values(output, label: str) -> list[str]:
    return [f.value for f in output.findings if f.label == label]


def labelled(output) -> dict[str, str]:
    return {f.label: f.value for f in output.findings}


def first(output, label: str):
    """The first finding carrying ``label``, so its severity and detail can be checked."""
    return next(f for f in output.findings if f.label == label)


# -- email profile (offline) -------------------------------------------------


async def test_email_reads_a_probable_name_from_the_local_part(ctx) -> None:
    output = await get_module("email").execute(parse_target("jane.doe@acmecorp.com"), ctx)

    name = first(output, "Probable name")
    assert name.value == "Jane Doe"
    assert name.severity is Severity.NOTABLE
    # The detail names the convention, which is the reusable part of the finding.
    assert "first.last@acmecorp.com" in name.detail


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("jane.doe@acmecorp.com", "Jane Doe"),
        ("jane_doe@acmecorp.com", "Jane Doe"),
        ("jane-doe@acmecorp.com", "Jane Doe"),
    ],
)
async def test_email_handles_each_name_separator(address: str, expected: str, ctx) -> None:
    output = await get_module("email").execute(parse_target(address), ctx)
    assert values(output, "Probable name") == [expected]


async def test_email_does_not_invent_a_name_from_an_opaque_local_part(ctx) -> None:
    output = await get_module("email").execute(parse_target("xk7f92@acmecorp.com"), ctx)
    assert values(output, "Probable name") == []


async def test_email_recognises_role_accounts(ctx) -> None:
    output = await get_module("email").execute(parse_target("support@example.com"), ctx)

    assert values(output, "Account type") == ["role account"]
    # A role account is not a person, so no name is guessed from it.
    assert values(output, "Probable name") == []


async def test_email_flags_disposable_providers(ctx) -> None:
    output = await get_module("email").execute(parse_target("x@mailinator.com"), ctx)

    provider = first(output, "Provider")
    assert "disposable" in provider.value
    assert provider.severity is Severity.WARNING


async def test_email_flags_privacy_providers(ctx) -> None:
    output = await get_module("email").execute(parse_target("x@proton.me"), ctx)
    assert "privacy-focused" in values(output, "Provider")[0]


async def test_email_extracts_subaddress_tags(ctx) -> None:
    output = await get_module("email").execute(parse_target("bob+netflix@gmail.com"), ctx)

    tag = first(output, "Sub-address tag")
    assert tag.value == "netflix"
    assert "bob@gmail.com" in tag.detail


async def test_email_marks_corporate_domains_as_worth_scanning(ctx) -> None:
    output = await get_module("email").execute(parse_target("someone@acmecorp.com"), ctx)

    provider = first(output, "Provider")
    assert "self-hosted or corporate" in provider.value
    assert provider.severity is Severity.NOTABLE


async def test_email_module_makes_no_requests(ctx) -> None:
    """The offline modules must not touch the network at all."""
    with respx.mock(assert_all_mocked=True):
        await get_module("email").execute(parse_target("jane.doe@acmecorp.com"), ctx)


# -- phone (offline) ---------------------------------------------------------


async def test_phone_describes_an_international_number(ctx) -> None:
    output = await get_module("phone").execute(parse_target("+442071838750"), ctx)
    found = labelled(output)

    assert found["Country"] == "GB"
    assert found["Country code"] == "+44"
    assert found["Region"] == "London"
    assert found["Validity"] == "valid and allocated"
    assert found["E.164"] == "+442071838750"


async def test_phone_reports_timezones(ctx) -> None:
    output = await get_module("phone").execute(parse_target("+14155550100"), ctx)
    assert "America/Los_Angeles" in values(output, "Timezone")


async def test_phone_flags_an_unallocated_number(ctx) -> None:
    output = await get_module("phone").execute(parse_target("+15555555555"), ctx)

    validity = first(output, "Validity")
    assert validity.severity is Severity.WARNING


async def test_phone_admits_when_a_national_number_is_ambiguous(ctx) -> None:
    """Without a country code or a configured region, do not guess."""
    output = await get_module("phone").execute(parse_target("415 555 0100"), ctx)

    country = first(output, "Country")
    assert country.value == "unknown"
    assert "WOSINT_PHONE_REGION" in country.detail
    assert country.severity is Severity.NOTABLE


async def test_phone_uses_the_configured_default_region(settings: Settings) -> None:
    settings.phone_region = "US"
    async with httpx.AsyncClient() as client:
        ctx = RunContext(settings=settings, client=client, timeout=5)
        output = await get_module("phone").execute(parse_target("415 555 0100"), ctx)

    assert labelled(output)["Country"] == "US"
    assert labelled(output)["E.164"] == "+14155550100"


async def test_phone_never_emits_the_unknown_timezone_placeholder(ctx) -> None:
    output = await get_module("phone").execute(parse_target("+15555555555"), ctx)
    assert "Etc/Unknown" not in values(output, "Timezone")


# -- search links (offline) --------------------------------------------------


async def test_links_quotes_the_target_as_an_exact_phrase(ctx) -> None:
    output = await get_module("links").execute(parse_target("Ada Lovelace"), ctx)

    google = values(output, "Google")[0]
    assert "%22Ada+Lovelace%22" in google


async def test_links_builds_site_scoped_searches_for_people(ctx) -> None:
    output = await get_module("links").execute(parse_target("Ada Lovelace"), ctx)

    assert any("site%3Alinkedin.com" in v for v in values(output, "LinkedIn search"))


async def test_links_builds_profile_urls_for_usernames(ctx) -> None:
    output = await get_module("links").execute(parse_target("some_user"), ctx)
    found = labelled(output)

    assert found["GitHub profile"] == "https://github.com/some_user"
    assert found["Reddit profile"] == "https://www.reddit.com/user/some_user"


async def test_links_searches_a_phone_number_with_and_without_country_code(ctx) -> None:
    output = await get_module("links").execute(parse_target("+14155550100"), ctx)

    assert any("%2B14155550100" in v for v in values(output, "Google"))
    assert any("%2214155550100%22" in v for v in values(output, "Google (digits only)"))


async def test_links_suggests_searching_an_email_local_part(ctx) -> None:
    output = await get_module("links").execute(parse_target("janedoe@example.com"), ctx)
    assert any("%22janedoe%22" in v for v in values(output, "Handle search"))


# -- Gravatar ----------------------------------------------------------------

GRAVATAR_PROFILE = {
    "entry": [
        {
            "displayName": "Beau",
            "name": {"formatted": "Beau Lebens"},
            "currentLocation": "Golden, CO",
            "profileUrl": "https://gravatar.com/beau",
            "accounts": [{"shortname": "github", "url": "https://github.com/beaulebens"}],
        }
    ]
}


@respx.mock
async def test_gravatar_extracts_the_profile_and_linked_accounts(ctx) -> None:
    digest = gravatar_hash("beau@example.com")
    respx.get(f"https://gravatar.com/{digest}.json").mock(
        return_value=httpx.Response(200, json=GRAVATAR_PROFILE)
    )
    output = await get_module("gravatar").execute(parse_target("beau@example.com"), ctx)
    found = labelled(output)

    assert found["Full name"] == "Beau Lebens"
    assert found["Location"] == "Golden, CO"
    assert found["Github"] == "https://github.com/beaulebens"


@respx.mock
async def test_gravatar_reports_an_avatar_without_a_public_profile(ctx) -> None:
    """A private profile with an avatar still proves the address is registered."""
    digest = gravatar_hash("matt@example.com")
    respx.get(f"https://gravatar.com/{digest}.json").mock(return_value=httpx.Response(404))
    respx.get(f"https://gravatar.com/avatar/{digest}").mock(return_value=httpx.Response(200))

    output = await get_module("gravatar").execute(parse_target("matt@example.com"), ctx)

    assert values(output, "Gravatar") == ["avatar registered, profile not public"]


@respx.mock
async def test_gravatar_reports_a_clean_miss(ctx) -> None:
    digest = gravatar_hash("nobody@example.com")
    respx.get(f"https://gravatar.com/{digest}.json").mock(return_value=httpx.Response(404))
    respx.get(f"https://gravatar.com/avatar/{digest}").mock(return_value=httpx.Response(404))

    output = await get_module("gravatar").execute(parse_target("nobody@example.com"), ctx)

    assert values(output, "Gravatar") == ["no public profile"]


@respx.mock
async def test_gravatar_does_not_pass_off_a_block_as_a_miss(ctx) -> None:
    """Only a 404 means "absent"; anything else is a failure worth reporting."""
    digest = gravatar_hash("someone@example.com")
    respx.get(f"https://gravatar.com/{digest}.json").mock(return_value=httpx.Response(429))

    with pytest.raises(HttpError):
        await get_module("gravatar").execute(parse_target("someone@example.com"), ctx)


def test_gravatar_hash_is_normalised() -> None:
    assert gravatar_hash("  Beau@Example.COM ") == gravatar_hash("beau@example.com")


# -- GitHub and GitLab -------------------------------------------------------


@respx.mock
async def test_github_extracts_volunteered_identity_details(ctx) -> None:
    respx.get("https://api.github.com/users/some_user").mock(
        return_value=httpx.Response(
            200,
            json={
                "login": "some_user",
                "html_url": "https://github.com/some_user",
                "name": "Jane Doe",
                "company": "@acmecorp",
                "location": "Berlin",
                "email": "jane@acmecorp.com",
                "twitter_username": "janedoe",
                "created_at": "2011-03-04T05:06:07Z",
                "public_repos": 42,
                "followers": 7,
            },
        )
    )
    output = await get_module("github").execute(parse_target("some_user"), ctx)
    found = labelled(output)

    assert found["Name"] == "Jane Doe"
    assert found["Location"] == "Berlin"
    assert found["Joined"] == "2011-03-04"
    assert found["Public repositories"] == "42"


@respx.mock
async def test_github_marks_a_published_email_as_a_warning(ctx) -> None:
    respx.get("https://api.github.com/users/some_user").mock(
        return_value=httpx.Response(200, json={"login": "some_user", "email": "jane@acmecorp.com"})
    )
    output = await get_module("github").execute(parse_target("some_user"), ctx)

    email = first(output, "Public email")
    assert email.severity is Severity.WARNING


@respx.mock
async def test_github_treats_a_missing_account_as_empty(ctx) -> None:
    respx.get("https://api.github.com/users/nobody").mock(return_value=httpx.Response(404))
    output = await get_module("github").execute(parse_target("nobody"), ctx)
    assert output.findings == []


@respx.mock
async def test_github_does_not_pass_off_a_block_as_a_missing_account(ctx) -> None:
    """A 403 from a rate limit or proxy must not read as "no such user"."""
    respx.get("https://api.github.com/users/some_user").mock(return_value=httpx.Response(403))

    with pytest.raises(HttpError):
        await get_module("github").execute(parse_target("some_user"), ctx)


@respx.mock
async def test_github_uses_an_email_local_part_as_the_handle(ctx) -> None:
    route = respx.get("https://api.github.com/users/janedoe").mock(return_value=httpx.Response(404))
    await get_module("github").execute(parse_target("janedoe@example.com"), ctx)
    assert route.called


@respx.mock
async def test_gitlab_reads_the_first_matching_user(ctx) -> None:
    respx.get("https://gitlab.com/api/v4/users").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"web_url": "https://gitlab.com/some_user", "name": "Jane Doe", "state": "active"}
            ],
        )
    )
    output = await get_module("gitlab").execute(parse_target("some_user"), ctx)
    found = labelled(output)

    assert found["GitLab"] == "https://gitlab.com/some_user"
    assert found["Name"] == "Jane Doe"


@respx.mock
async def test_gitlab_handles_no_match(ctx) -> None:
    respx.get("https://gitlab.com/api/v4/users").mock(return_value=httpx.Response(200, json=[]))
    output = await get_module("gitlab").execute(parse_target("nobody"), ctx)
    assert output.findings == []


# -- Have I Been Pwned -------------------------------------------------------


def test_hibp_is_unavailable_without_a_key() -> None:
    availability = get_module("hibp").availability(Settings())

    assert not availability.ok
    assert "WOSINT_KEY_HIBP" in availability.reason


def test_hibp_becomes_available_once_a_key_is_set() -> None:
    assert get_module("hibp").availability(Settings(api_keys={"hibp": "k"})).ok


@respx.mock
async def test_hibp_sends_the_configured_key(ctx) -> None:
    ctx.settings.api_keys["hibp"] = "secret-key"
    route = respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/bob@example.com").mock(
        return_value=httpx.Response(200, json=[])
    )
    await get_module("hibp").execute(parse_target("bob@example.com"), ctx)

    assert route.calls[0].request.headers["hibp-api-key"] == "secret-key"


@respx.mock
async def test_hibp_reports_breaches_and_flags_sensitive_leaks(ctx) -> None:
    respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/bob@example.com").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "Name": "Adobe",
                    "BreachDate": "2013-10-04",
                    "DataClasses": ["Email addresses", "Passwords"],
                },
                {"Name": "Forum", "BreachDate": "2016-01-01", "DataClasses": ["Usernames"]},
            ],
        )
    )
    output = await get_module("hibp").execute(parse_target("bob@example.com"), ctx)

    by_value = {f.value: f for f in output.findings if f.label == "Breach"}
    assert by_value["Adobe"].severity is Severity.WARNING
    assert "passwords" in by_value["Adobe"].detail
    assert by_value["Forum"].severity is Severity.NOTABLE


@respx.mock
async def test_hibp_treats_404_as_good_news(ctx) -> None:
    """HIBP answers "not breached" with a 404, which is not an error."""
    respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/bob@example.com").mock(
        return_value=httpx.Response(404)
    )
    output = await get_module("hibp").execute(parse_target("bob@example.com"), ctx)

    assert values(output, "Breaches") == ["none known"]


@respx.mock
async def test_hibp_surfaces_an_invalid_key(ctx) -> None:
    respx.get("https://haveibeenpwned.com/api/v3/breachedaccount/bob@example.com").mock(
        return_value=httpx.Response(401)
    )
    with pytest.raises(HttpError):
        await get_module("hibp").execute(parse_target("bob@example.com"), ctx)
