"""Target parsing and classification.

Everything a user can type into the search bar is normalised into a
:class:`Target` here.  Modules declare which :class:`TargetType` values they
understand, which is how the runner decides what to execute for a given input.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlsplit


class TargetType(str, Enum):
    """The kind of artefact a target represents."""

    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    URL = "url"
    USERNAME = "username"
    PHONE = "phone"
    PERSON = "person"

    @property
    def label(self) -> str:
        return {
            TargetType.DOMAIN: "Domain",
            TargetType.IPV4: "IPv4 address",
            TargetType.IPV6: "IPv6 address",
            TargetType.EMAIL: "Email address",
            TargetType.URL: "URL",
            TargetType.USERNAME: "Username",
            TargetType.PHONE: "Phone number",
            TargetType.PERSON: "Person",
        }[self]


IP_TYPES = frozenset({TargetType.IPV4, TargetType.IPV6})

#: Targets that identify a person rather than a piece of infrastructure.
#: Modules that handle these are working with personal data, which the UI
#: points out and which carries obligations infrastructure scanning does not.
PERSONAL_TYPES = frozenset(
    {TargetType.EMAIL, TargetType.USERNAME, TargetType.PHONE, TargetType.PERSON}
)

# A hostname label: alphanumerics and hyphens, not starting or ending with one.
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
# The final label is stricter than the rest. A real TLD is alphabetic, or an
# "xn--" punycode label; requiring that is what keeps a username such as
# "user.name-1" from being mistaken for a domain.
_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*\.{_TLD}$", re.IGNORECASE)
_EMAIL_RE = re.compile(rf"^[^@\s]+@({_LABEL}(?:\.{_LABEL})+)$", re.IGNORECASE)
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,38}$", re.IGNORECASE)

# A phone number as people write them: an optional international prefix, then
# digits broken up by spaces, dots, hyphens or brackets.
_PHONE_RE = re.compile(r"^(?:\+|00)?[\d\s().-]{6,24}$")
#: E.164 allows at most 15 digits, and no real number has fewer than 7.
_MIN_PHONE_DIGITS = 7
_MAX_PHONE_DIGITS = 15

# A person's name: two to five words of letters, allowing the hyphens,
# apostrophes and accents that real names contain.
_NAME_WORD = r"[^\W\d_][\w'\u2019-]*"
_PERSON_RE = re.compile(rf"^{_NAME_WORD}(?:\s+{_NAME_WORD}){{1,4}}$", re.UNICODE)


class TargetError(ValueError):
    """Raised when user input cannot be interpreted as a scannable target."""


@dataclass(frozen=True, slots=True)
class Target:
    """A normalised scan target.

    Attributes:
        value: The canonical form of the target (lower-cased, scheme stripped).
        type: What kind of artefact ``value`` is.
        raw: Exactly what the user typed, kept for display and reporting.
    """

    value: str
    type: TargetType
    raw: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @property
    def domain(self) -> str | None:
        """The domain associated with this target, if it has one.

        URLs and email addresses both carry a domain that DNS- and
        certificate-oriented modules can work with.
        """
        if self.type is TargetType.DOMAIN:
            return self.value
        if self.type is TargetType.EMAIL:
            return self.value.split("@", 1)[1]
        if self.type is TargetType.URL:
            host = urlsplit(self.value).hostname
            return host if host and _DOMAIN_RE.match(host) else None
        return None

    @property
    def is_ip(self) -> bool:
        return self.type in IP_TYPES

    @property
    def is_personal(self) -> bool:
        """Whether this target identifies a person rather than infrastructure."""
        return self.type in PERSONAL_TYPES


def phone_digits(value: str) -> str:
    """The digits of ``value``, with ``00`` international prefixes normalised.

    ``00`` and ``+`` mean the same thing at the start of a dialled number, so
    both end up as a bare country code here.
    """
    stripped = value.strip()
    if stripped.startswith("00"):
        stripped = stripped[2:]
    return re.sub(r"\D", "", stripped)


def _looks_like_a_phone_number(value: str) -> bool:
    if not _PHONE_RE.match(value):
        return False
    digits = phone_digits(value)
    return _MIN_PHONE_DIGITS <= len(digits) <= _MAX_PHONE_DIGITS


def detect_target_type(value: str) -> TargetType:
    """Classify a raw string.

    The order matters: an IP literal is checked before the domain pattern so
    that ``1.2.3.4`` is not mistaken for a hostname, and the username fallback
    is only reached once every more specific shape has been ruled out.

    Raises:
        TargetError: If the value is empty or matches no known shape.
    """
    candidate = value.strip()
    if not candidate:
        raise TargetError("Enter a target to scan.")

    if "://" in candidate:
        parts = urlsplit(candidate)
        if parts.scheme in ("http", "https") and parts.hostname:
            return TargetType.URL
        raise TargetError(f"Unsupported URL scheme: {parts.scheme or candidate!r}")

    if _EMAIL_RE.match(candidate):
        return TargetType.EMAIL

    bare = candidate.strip("[]")
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        pass
    else:
        return TargetType.IPV4 if ip.version == 4 else TargetType.IPV6

    # Phone numbers are checked before domains because a number written as
    # "415.555.0100" is dotted, and before usernames because a bare run of
    # digits is a far more likely phone number than a handle.
    if _looks_like_a_phone_number(candidate):
        return TargetType.PHONE

    if _DOMAIN_RE.match(candidate):
        return TargetType.DOMAIN

    if _USERNAME_RE.match(candidate):
        return TargetType.USERNAME

    if _PERSON_RE.match(candidate):
        return TargetType.PERSON

    raise TargetError(f"Could not work out what kind of target {candidate!r} is.")


def parse_target(value: str) -> Target:
    """Turn raw user input into a :class:`Target`.

    Raises:
        TargetError: If the input cannot be classified.
    """
    raw = value.strip()
    target_type = detect_target_type(raw)

    if target_type is TargetType.URL:
        parts = urlsplit(raw)
        normalised = parts._replace(
            scheme=parts.scheme.lower(),
            netloc=parts.netloc.lower(),
            fragment="",
        ).geturl()
    elif target_type in IP_TYPES:
        normalised = str(ipaddress.ip_address(raw.strip("[]")))
    elif target_type is TargetType.PHONE:
        # Store the dialable form. The leading "+" is kept only when the input
        # actually carried a country code, so a national number is not silently
        # promoted to an international one.
        digits = phone_digits(raw)
        normalised = f"+{digits}" if raw.lstrip().startswith(("+", "00")) else digits
    elif target_type is TargetType.PERSON:
        # Names keep their capitalisation; collapsing runs of whitespace is the
        # only tidying that is safe to do.
        normalised = " ".join(raw.split())
    else:
        normalised = raw.lower().rstrip(".")

    return Target(value=normalised, type=target_type, raw=raw)
