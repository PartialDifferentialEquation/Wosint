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
