"""Entity extraction, merging, linking and pivot suggestion."""

from __future__ import annotations

import pytest

from wosint.core.correlate import Investigation, handle_from_url
from wosint.core.entities import Entity, EntityType, RelationKind, Source, normalise
from wosint.core.models import Finding, ModuleResult, ModuleStatus, Scan, Severity
from wosint.core.targets import TargetType, parse_target


def scan_with(target: str, module: str, findings: list[Finding]) -> Scan:
    """A finished scan carrying one module's findings."""
    scan = Scan(target=parse_target(target))
    scan.results[module] = ModuleResult(
        module=module, title=module, kind="api", status=ModuleStatus.OK, findings=findings
    )
    scan.finished_at = scan.started_at
    return scan


# -- normalisation -----------------------------------------------------------


@pytest.mark.parametrize(
    ("entity_type", "raw", "expected"),
    [
        (EntityType.EMAIL, "  Bob@Example.COM ", "bob@example.com"),
        (EntityType.USERNAME, "SomeUser", "someuser"),
        (EntityType.PHONE, "+1 (415) 555-0100", "+14155550100"),
        (EntityType.DOMAIN, "Example.COM.", "example.com"),
        (EntityType.URL, "https://example.com/x/", "https://example.com/x"),
        (EntityType.PERSON_NAME, "Doe,  Jane", "doe jane"),
        (EntityType.ORGANISATION, "@Acme Corp, Inc.", "acme"),
    ],
)
def test_normalisation(entity_type: EntityType, raw: str, expected: str) -> None:
    assert normalise(entity_type, raw) == expected


# -- handle extraction -------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/beaulebens", "beaulebens"),
        ("https://x.com/janedoe", "janedoe"),
        ("https://twitter.com/janedoe", "janedoe"),
        ("https://www.reddit.com/user/janedoe", "janedoe"),
        ("https://reddit.com/u/janedoe", "janedoe"),
        ("https://www.linkedin.com/in/jane-doe-123/", "jane-doe-123"),
        ("https://www.tiktok.com/@janedoe", "janedoe"),
        ("https://medium.com/@janedoe", "janedoe"),
        ("https://t.me/janedoe", "janedoe"),
    ],
)
def test_handle_is_read_from_known_profile_urls(url: str, expected: str) -> None:
    assert handle_from_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/janedoe",  # unknown site shape
        "https://github.com/acme/project",  # a repository, not a profile
        "https://x.com/search",  # the site's own page
        "not a url",
    ],
)
def test_no_handle_is_invented_from_unknown_shapes(url: str) -> None:
    """A wrong handle would send the analyst down a chain about someone else."""
    assert handle_from_url(url) is None


# -- extraction --------------------------------------------------------------


def test_scanned_target_becomes_an_entity() -> None:
    investigation = Investigation()
    investigation.add_scan(scan_with("bob@example.com", "email", []))

    assert (EntityType.EMAIL, "bob@example.com") in investigation.entities
    assert investigation.scanned == ["bob@example.com"]


def test_names_and_locations_are_extracted() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "some_user",
            "github",
            [
                Finding("profile", "Name", "Jane Doe"),
                Finding("profile", "Location", "Berlin"),
                Finding("profile", "Company", "@acmecorp"),
            ],
        )
    )

    assert [e.display for e in investigation.of_type(EntityType.PERSON_NAME)] == ["Jane Doe"]
    assert [e.display for e in investigation.of_type(EntityType.LOCATION)] == ["Berlin"]
    assert [e.display for e in investigation.of_type(EntityType.ORGANISATION)] == ["@acmecorp"]


def test_account_findings_yield_both_an_account_and_a_handle() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "bob@example.com",
            "gravatar",
            [Finding("account", "Github", "https://github.com/beaulebens")],
        )
    )

    assert [e.display for e in investigation.of_type(EntityType.ACCOUNT)] == [
        "https://github.com/beaulebens"
    ]
    assert [e.display for e in investigation.of_type(EntityType.USERNAME)] == ["beaulebens"]


def test_emails_inside_free_text_are_picked_up() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "some_user",
            "github",
            [Finding("profile", "Bio", "Reach me at jane@acmecorp.com for work")],
        )
    )

    assert [e.value for e in investigation.of_type(EntityType.EMAIL)] == ["jane@acmecorp.com"]


def test_infrastructure_findings_do_not_pollute_a_person_profile() -> None:
    """A certificate's subdomains say nothing about who someone is."""
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "example.com",
            "crtsh",
            [
                Finding("certificate", "Subdomain", "www.example.com"),
                Finding("dns", "A record", "1.2.3.4"),
            ],
        )
    )

    assert investigation.of_type(EntityType.URL) == []
    assert investigation.of_type(EntityType.PERSON_NAME) == []


def test_search_links_are_not_treated_as_evidence() -> None:
    """We built those URLs ourselves; they are leads, not findings."""
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "Ada Lovelace",
            "links",
            [Finding("search", "Google", "https://www.google.com/search?q=%22Ada+Lovelace%22")],
        )
    )

    assert investigation.of_type(EntityType.URL) == []


def test_scan_metadata_is_not_mistaken_for_an_entity() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "bob@example.com",
            "holehe",
            [Finding("account", "Accounts found", "7"), Finding("meta", "Rate limit", "hit")],
        )
    )

    assert investigation.of_type(EntityType.ACCOUNT) == []


# -- merging and confidence --------------------------------------------------


def test_the_same_value_from_two_modules_becomes_one_entity() -> None:
    investigation = Investigation()
    for module in ("gravatar", "github"):
        investigation.add_scan(
            scan_with("some_user", module, [Finding("profile", "Name", "Jane Doe")])
        )

    names = investigation.of_type(EntityType.PERSON_NAME)
    assert len(names) == 1
    assert names[0].modules == {"gravatar", "github"}


def test_confidence_rises_with_independent_corroboration() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with("some_user", "github", [Finding("profile", "Name", "Jane Doe")])
    )
    single = investigation.of_type(EntityType.PERSON_NAME)[0].confidence

    investigation.add_scan(
        scan_with("some_user", "gravatar", [Finding("profile", "Name", "Jane Doe")])
    )
    corroborated = investigation.of_type(EntityType.PERSON_NAME)[0].confidence

    assert corroborated > single


def test_repeating_one_module_does_not_raise_confidence() -> None:
    """Saying the same thing twice is not corroboration."""
    investigation = Investigation()
    finding = Finding("profile", "Name", "Jane Doe")
    investigation.add_scan(scan_with("some_user", "github", [finding, finding]))

    assert investigation.of_type(EntityType.PERSON_NAME)[0].confidence == 0.5


def test_being_seen_from_two_starting_points_counts_for_more() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with("bob@example.com", "gravatar", [Finding("profile", "Name", "Jane Doe")])
    )
    from_one = investigation.of_type(EntityType.PERSON_NAME)[0].confidence

    investigation.add_scan(
        scan_with("some_user", "gravatar", [Finding("profile", "Name", "Jane Doe")])
    )
    from_two = investigation.of_type(EntityType.PERSON_NAME)[0].confidence

    assert from_two > from_one


def test_case_differences_do_not_split_an_entity() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with("some_user", "github", [Finding("profile", "Public email", "Bob@Example.COM")])
    )
    investigation.add_scan(
        scan_with("some_user", "gravatar", [Finding("profile", "Email", "bob@example.com")])
    )

    assert len(investigation.of_type(EntityType.EMAIL)) == 1


def test_merging_a_different_entity_is_refused() -> None:
    left = Entity(EntityType.EMAIL, "a@example.com")
    right = Entity(EntityType.EMAIL, "b@example.com")

    with pytest.raises(ValueError, match="cannot merge"):
        left.merge(right)


# -- relations ---------------------------------------------------------------


def test_discovered_entities_are_linked_to_the_scanned_subject() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "bob@example.com",
            "gravatar",
            [Finding("account", "Github", "https://github.com/janedoe")],
        )
    )

    subject = investigation.entities[(EntityType.EMAIL, "bob@example.com")]
    related = investigation.related_to(subject)

    kinds = {relation.kind for relation, _ in related}
    assert RelationKind.OWNS in kinds
    assert all(relation.reason for relation, _ in related)


def test_relations_are_not_duplicated_across_repeat_scans() -> None:
    investigation = Investigation()
    for _ in range(3):
        investigation.add_scan(
            scan_with("bob@example.com", "gravatar", [Finding("profile", "Name", "Jane Doe")])
        )

    assert len(investigation.relations) == 1


# -- pivots ------------------------------------------------------------------


def test_pivots_offer_scannable_identifiers() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "bob@example.com",
            "gravatar",
            [
                Finding("account", "Github", "https://github.com/janedoe"),
                Finding("profile", "Location", "Berlin"),
            ],
        )
    )

    pivots = {p.value: p for p in investigation.pivots()}

    assert "janedoe" in pivots
    assert pivots["janedoe"].type is TargetType.USERNAME
    # A location is not something you can scan.
    assert "Berlin" not in pivots


def test_pivots_explain_where_they_came_from() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "bob@example.com",
            "gravatar",
            [Finding("account", "Github", "https://github.com/janedoe")],
        )
    )

    pivot = next(p for p in investigation.pivots() if p.value == "janedoe")
    assert "gravatar" in pivot.reason


def test_already_scanned_pivots_are_marked_and_sorted_last() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "bob@example.com",
            "gravatar",
            [Finding("account", "Github", "https://github.com/janedoe")],
        )
    )

    pivots = investigation.pivots()
    done = [p for p in pivots if p.scanned]

    assert [p.value for p in done] == ["bob@example.com"]
    assert pivots[-1].scanned


def test_unparseable_values_are_not_offered_as_pivots() -> None:
    investigation = Investigation()
    investigation.add_entity(
        Entity(
            EntityType.USERNAME,
            "not a valid handle!!",
            sources=[Source("test", "Handle")],
        )
    )

    assert all(p.value != "not a valid handle!!" for p in investigation.pivots())


# -- serialisation -----------------------------------------------------------


def test_investigation_serialises_with_provenance() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "bob@example.com",
            "gravatar",
            [Finding("profile", "Name", "Jane Doe", "from the profile", Severity.NOTABLE)],
        )
    )

    payload = investigation.as_dict()
    name = next(e for e in payload["entities"] if e["type"] == "person_name")

    assert name["display"] == "Jane Doe"
    assert name["sources"][0]["module"] == "gravatar"
    assert name["sources"][0]["target"] == "bob@example.com"
    assert payload["scanned"] == ["bob@example.com"]


# -- inferred claims ---------------------------------------------------------


def inferred_finding(label: str, value: str) -> Finding:
    return Finding("profile", label, value, "handle guessed", inferred=True)


def test_an_entity_resting_only_on_guesses_is_marked_inferred() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with("beau@example.com", "gitlab", [inferred_finding("Name", "Somebody Else")])
    )

    name = investigation.of_type(EntityType.PERSON_NAME)[0]
    assert name.is_inferred
    assert name.confidence == 0.25
    assert name.corroboration == "inferred, unconfirmed"


def test_repeating_a_guess_does_not_confirm_it() -> None:
    """Two modules guessing the same wrong handle is not corroboration."""
    investigation = Investigation()
    for module in ("github", "gitlab"):
        investigation.add_scan(
            scan_with("beau@example.com", module, [inferred_finding("Name", "Somebody Else")])
        )

    assert investigation.of_type(EntityType.PERSON_NAME)[0].confidence == 0.25


def test_one_confirmed_source_promotes_an_inferred_entity() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with("beau@example.com", "gitlab", [inferred_finding("Name", "Jane Doe")])
    )
    investigation.add_scan(
        scan_with("beau@example.com", "gravatar", [Finding("profile", "Full name", "Jane Doe")])
    )

    name = investigation.of_type(EntityType.PERSON_NAME)[0]
    assert not name.is_inferred
    assert name.confidence > 0.25


def test_a_guessed_identifier_is_never_offered_as_a_pivot() -> None:
    """Chaining off a guess is how two different people become one profile."""
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "beau@example.com",
            "gitlab",
            [Finding("account", "GitLab", "https://gitlab.com/beau", "guessed", inferred=True)],
        )
    )

    assert all(p.value != "beau" for p in investigation.pivots())


def test_a_confirmed_identifier_is_offered_as_a_pivot() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "beau@example.com",
            "gravatar",
            [Finding("account", "GitLab", "https://gitlab.com/beau")],
        )
    )

    assert any(p.value == "beau" for p in investigation.pivots())


def test_inferred_entities_are_kept_out_of_the_identifier_list() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with(
            "beau@example.com",
            "gitlab",
            [Finding("account", "GitLab", "https://gitlab.com/beau", "guessed", inferred=True)],
        )
    )

    assert all(e.value != "beau" for e in investigation.identifiers)


def test_serialised_entities_carry_the_inferred_flag() -> None:
    investigation = Investigation()
    investigation.add_scan(
        scan_with("beau@example.com", "gitlab", [inferred_finding("Name", "Somebody Else")])
    )

    name = next(e for e in investigation.as_dict()["entities"] if e["type"] == "person_name")
    assert name["inferred"] is True
    assert name["sources"][0]["inferred"] is True
