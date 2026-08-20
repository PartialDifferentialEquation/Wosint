"""Target classification and normalisation."""

from __future__ import annotations

import pytest

from wosint.core.targets import TargetError, TargetType, detect_target_type, parse_target


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", TargetType.DOMAIN),
        ("sub.example.co.uk", TargetType.DOMAIN),
        ("xn--bcher-kva.example", TargetType.DOMAIN),
        ("1.2.3.4", TargetType.IPV4),
        ("192.168.0.1", TargetType.IPV4),
        ("2001:db8::1", TargetType.IPV6),
        ("[2001:db8::1]", TargetType.IPV6),
        ("bob@example.com", TargetType.EMAIL),
        ("https://example.com/path", TargetType.URL),
        ("http://example.com", TargetType.URL),
        ("some_user", TargetType.USERNAME),
        ("user.name-1", TargetType.USERNAME),
    ],
)
def test_detects_target_type(value: str, expected: TargetType) -> None:
    assert detect_target_type(value) is expected


@pytest.mark.parametrize("value", ["", "   ", "ftp://example.com", "not a target!", "@@@"])
def test_rejects_unusable_input(value: str) -> None:
    with pytest.raises(TargetError):
        detect_target_type(value)


def test_ip_wins_over_domain_pattern() -> None:
    """A dotted quad must not be treated as a hostname."""
    assert detect_target_type("8.8.8.8") is TargetType.IPV4


def test_normalises_case_and_trailing_dot() -> None:
    target = parse_target("  Example.COM.  ")
    assert target.value == "example.com"
    assert target.raw == "Example.COM."


def test_normalises_url_and_drops_fragment() -> None:
    target = parse_target("HTTPS://Example.COM/Path?q=1#frag")
    assert target.value == "https://example.com/Path?q=1"
    assert target.domain == "example.com"


def test_normalises_ipv6() -> None:
    assert parse_target("[2001:0DB8::0001]").value == "2001:db8::1"


@pytest.mark.parametrize(
    ("value", "expected_domain"),
    [
        ("example.com", "example.com"),
        ("bob@example.com", "example.com"),
        ("https://a.example.com/x", "a.example.com"),
        ("1.2.3.4", None),
        ("some_user", None),
    ],
)
def test_domain_property(value: str, expected_domain: str | None) -> None:
    assert parse_target(value).domain == expected_domain


def test_is_ip() -> None:
    assert parse_target("1.2.3.4").is_ip
    assert parse_target("2001:db8::1").is_ip
    assert not parse_target("example.com").is_ip


# -- phone numbers -----------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "+14155550100",
        "+1 415 555 0100",
        "(415) 555-0100",
        "415.555.0100",
        "00 44 20 7183 8750",
        "555-1234",
    ],
)
def test_detects_phone_numbers(value: str) -> None:
    assert detect_target_type(value) is TargetType.PHONE


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("+1 (415) 555-0100", "+14155550100"),
        ("00442071838750", "+442071838750"),
        ("415.555.0100", "4155550100"),
    ],
)
def test_normalises_phone_numbers(value: str, expected: str) -> None:
    """A national number must not be silently promoted to an international one."""
    assert parse_target(value).value == expected


def test_phone_beats_domain_for_a_dotted_number() -> None:
    assert detect_target_type("415.555.0100") is TargetType.PHONE


def test_short_digit_runs_are_not_phone_numbers() -> None:
    """Six digits is below the shortest real number, so it stays a username."""
    assert detect_target_type("12345") is TargetType.USERNAME


def test_over_length_digit_runs_are_not_phone_numbers() -> None:
    """E.164 tops out at 15 digits."""
    assert detect_target_type("1234567890123456") is TargetType.USERNAME


# -- people ------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["John Smith", "Ada Lovelace", "Jean-Luc Picard", "Renée O'Brien", "María José García Ruiz"],
)
def test_detects_person_names(value: str) -> None:
    assert detect_target_type(value) is TargetType.PERSON


def test_person_names_keep_their_capitalisation() -> None:
    assert parse_target("  Ada   Lovelace  ").value == "Ada Lovelace"


def test_a_single_word_is_read_as_a_username() -> None:
    """One word is ambiguous; a handle is the more useful reading."""
    assert detect_target_type("Ada") is TargetType.USERNAME


@pytest.mark.parametrize(
    ("value", "personal"),
    [
        ("bob@example.com", True),
        ("some_user", True),
        ("+14155550100", True),
        ("Ada Lovelace", True),
        ("example.com", False),
        ("1.2.3.4", False),
        ("https://example.com", False),
    ],
)
def test_personal_targets_are_flagged(value: str, personal: bool) -> None:
    assert parse_target(value).is_personal is personal


def test_phone_digits_strips_formatting_and_prefixes() -> None:
    from wosint.core.targets import phone_digits

    assert phone_digits("+1 (415) 555-0100") == "14155550100"
    assert phone_digits("00442071838750") == "442071838750"
