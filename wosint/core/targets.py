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
from pathlib import Path
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
    IMAGE = "image"

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
            TargetType.IMAGE: "Image",
        }[self]


IP_TYPES = frozenset({TargetType.IPV4, TargetType.IPV6})

#: Targets that identify a person rather than a piece of infrastructure.
#: Modules that handle these are working with personal data, which the UI
#: points out and which carries obligations infrastructure scanning does not.
PERSONAL_TYPES = frozenset(
    {
        TargetType.EMAIL,
        TargetType.USERNAME,
        TargetType.PHONE,
        TargetType.PERSON,
        # A photograph is about a person more often than not, and its metadata
        # can place one at a time and place -- so it gets the same warning.
        TargetType.IMAGE,
    }
)

#: File suffixes accepted as image targets.
IMAGE_SUFFIXES = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".tif", ".tiff", ".heic"})

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
# When the analyst says "this is a name", a single word is allowed: auto-detection
# reads "Beau" as a username because that is the safer guess, but being told
# otherwise settles it.
_PERSON_COERCE_RE = re.compile(rf"^{_NAME_WORD}(?:\s+{_NAME_WORD}){{0,5}}$", re.UNICODE)


class TargetError(ValueError):
    """Raised when user input cannot be interpreted as a scannable target."""


@dataclass(frozen=True, slots=True)
class Target:
    """A normalised scan target.

    Attributes:
        value: The canonical form of the target (lower-cased, scheme stripped).
        type: What kind of artefact ``value`` is.
        raw: Exactly what the user typed, kept for display and reporting.
        hint: An optional qualifier for this scan, such as what a photograph is
            of. Modules that understand a hint use it to narrow what they look
            for; every other module ignores it.
    """

    value: str
    type: TargetType
    raw: str
    hint: str = ""

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


def _image_suffix(value: str) -> bool:
    """Whether ``value`` names a file with an image extension."""
    return Path(value).suffix.lower() in IMAGE_SUFFIXES


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

    if _image_suffix(candidate):
        if not Path(candidate).expanduser().is_file():
            raise TargetError(f"No such image file: {candidate}")
        return TargetType.IMAGE

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


def parse_target(value: str, *, hint: str = "") -> Target:
    """Turn raw user input into a :class:`Target`, working out its type.

    Args:
        value: What the analyst typed.
        hint: Optional per-scan qualifier passed through to the target.

    Raises:
        TargetError: If the input cannot be classified.
    """
    raw = value.strip()
    target_type = detect_target_type(raw)
    return Target(value=_normalise(raw, target_type), type=target_type, raw=raw, hint=hint)


def coerce_target(value: str, target_type: TargetType, *, hint: str = "") -> Target:
    """Read ``value`` as ``target_type``, overriding what detection would guess.

    Auto-detection has to pick the safest reading of an ambiguous string, which
    is not always the right one: a one-word name reads as a username, and a bare
    run of digits reads as a phone number. This is how an analyst says which it
    actually is.

    The override still has to be possible -- forcing ``"not a domain!!"`` to be a
    domain is refused rather than producing a target no module can use.

    Raises:
        TargetError: If ``value`` cannot be read as ``target_type``.
    """
    raw = value.strip()
    if not raw:
        raise TargetError("Enter a target to scan.")

    validate = _COERCION_CHECKS.get(target_type)
    if validate is not None and not validate(raw):
        label = target_type.label.lower()
        article = "an" if label[0] in "aeiou" else "a"
        raise TargetError(f"{raw!r} cannot be read as {article} {label}.")

    return Target(value=_normalise(raw, target_type), type=target_type, raw=raw, hint=hint)


def _normalise(raw: str, target_type: TargetType) -> str:
    """The canonical form of ``raw`` when read as ``target_type``."""
    if target_type is TargetType.URL:
        # A bare hostname coerced to a URL needs a scheme to be fetchable.
        candidate = raw if "://" in raw else f"https://{raw}"
        parts = urlsplit(candidate)
        return parts._replace(
            scheme=parts.scheme.lower(),
            netloc=parts.netloc.lower(),
            fragment="",
        ).geturl()
    if target_type in IP_TYPES:
        return str(ipaddress.ip_address(raw.strip("[]")))
    if target_type is TargetType.PHONE:
        # Store the dialable form. The leading "+" is kept only when the input
        # actually carried a country code, so a national number is not silently
        # promoted to an international one.
        digits = phone_digits(raw)
        return f"+{digits}" if raw.lstrip().startswith(("+", "00")) else digits
    if target_type is TargetType.IMAGE:
        return str(Path(raw).expanduser().resolve())
    if target_type is TargetType.PERSON:
        # Names keep their capitalisation; collapsing runs of whitespace is the
        # only tidying that is safe to do.
        return " ".join(raw.split())
    return raw.lower().rstrip(".")


def _is_ip_version(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value.strip("[]")).version == version
    except ValueError:
        return False


def _is_url(value: str) -> bool:
    """Whether ``value`` is a URL, or a hostname one can be built from."""
    if "://" not in value:
        return bool(_DOMAIN_RE.match(value))
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def _is_image(value: str) -> bool:
    return _image_suffix(value) and Path(value).expanduser().is_file()


#: What each type will accept when it is chosen explicitly. Anything absent
#: here accepts whatever it is given.
_COERCION_CHECKS = {
    TargetType.DOMAIN: lambda v: bool(_DOMAIN_RE.match(v)),
    TargetType.IPV4: lambda v: _is_ip_version(v, 4),
    TargetType.IPV6: lambda v: _is_ip_version(v, 6),
    TargetType.EMAIL: lambda v: bool(_EMAIL_RE.match(v)),
    TargetType.URL: _is_url,
    TargetType.USERNAME: lambda v: bool(_USERNAME_RE.match(v)),
    TargetType.PHONE: _looks_like_a_phone_number,
    TargetType.PERSON: lambda v: bool(_PERSON_COERCE_RE.match(v)),
    TargetType.IMAGE: _is_image,
}
