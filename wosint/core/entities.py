"""Typed entities extracted from findings.

A :class:`~wosint.core.models.Finding` is a statement one module made about a
target.  An :class:`Entity` is the *thing* that statement was about, normalised
so the same address found by four different modules becomes one entity with
four sources rather than four unrelated rows.

Normalising is what makes correlation possible: ``Bob@Example.COM`` from a
Gravatar profile and ``bob@example.com`` from a GitHub profile are the same
person's mailbox, and nothing downstream can notice that unless they are
written the same way first.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .targets import TargetType, phone_digits


class InvestigationError(ValueError):
    """A saved investigation could not be read back.

    Raised rather than silently repairing a file: a profile that quietly loses
    the provenance behind a claim is worse than one that refuses to open.
    """


class EntityType(str, Enum):
    """The kind of thing an entity is."""

    PERSON_NAME = "person_name"
    EMAIL = "email"
    USERNAME = "username"
    PHONE = "phone"
    ACCOUNT = "account"
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    ORGANISATION = "organisation"
    LOCATION = "location"
    BREACH = "breach"
    DOCUMENT = "document"

    @property
    def label(self) -> str:
        return {
            EntityType.PERSON_NAME: "Name",
            EntityType.EMAIL: "Email address",
            EntityType.USERNAME: "Username",
            EntityType.PHONE: "Phone number",
            EntityType.ACCOUNT: "Account",
            EntityType.DOMAIN: "Domain",
            EntityType.IP: "IP address",
            EntityType.URL: "URL",
            EntityType.ORGANISATION: "Organisation",
            EntityType.LOCATION: "Location",
            EntityType.BREACH: "Breach",
            EntityType.DOCUMENT: "Document",
        }[self]

    @property
    def is_identifier(self) -> bool:
        """Whether this type identifies a person strongly enough to pivot on.

        Names and locations are deliberately excluded: two people share a name
        far too often for it to be treated as an identifier on its own.
        """
        return self in (
            EntityType.EMAIL,
            EntityType.USERNAME,
            EntityType.PHONE,
            EntityType.ACCOUNT,
        )


#: Entity types that a scan can be run against, and the target type to use.
#: Confidence given to an entity that rests only on guesses.
INFERRED_CONFIDENCE = 0.25

PIVOTABLE: dict[EntityType, TargetType] = {
    EntityType.EMAIL: TargetType.EMAIL,
    EntityType.USERNAME: TargetType.USERNAME,
    EntityType.PHONE: TargetType.PHONE,
    EntityType.DOMAIN: TargetType.DOMAIN,
    EntityType.IP: TargetType.IPV4,
    EntityType.PERSON_NAME: TargetType.PERSON,
    EntityType.URL: TargetType.URL,
}


@dataclass(frozen=True, slots=True)
class Source:
    """Where an entity came from: one module's claim, kept for provenance.

    Nothing in a profile should be un-attributable. Every assertion the
    correlator makes can be traced back to the module and finding that produced
    it, because an analyst has to be able to check the working.
    """

    module: str
    label: str
    detail: str = ""
    scan_id: str = ""
    target: str = ""
    #: Whether the claim rests on a guess the module made rather than on the
    #: source confirming it.
    inferred: bool = False

    def __str__(self) -> str:  # pragma: no cover - display helper
        return f"{self.label} ({self.module})"

    @classmethod
    def from_dict(cls, data: Any) -> Source:
        """Read a source back from an exported profile.

        The module is required. A claim that cannot name who made it is not a
        source, and importing one would put an unattributable line into a
        profile that is supposed to be auditable end to end.
        """
        if not isinstance(data, Mapping):
            raise InvestigationError("a source must be an object")
        module = str(data.get("module") or "").strip()
        if not module:
            raise InvestigationError("a source is missing the module that made the claim")
        return cls(
            module=module,
            label=str(data.get("label") or "").strip(),
            detail=str(data.get("detail") or ""),
            scan_id=str(data.get("scan_id") or ""),
            target=str(data.get("target") or ""),
            inferred=bool(data.get("inferred", False)),
        )


@dataclass(slots=True)
class Entity:
    """One normalised thing, with every source that attested to it.

    Attributes:
        type: What kind of thing this is.
        value: The normalised form, used as the identity key.
        display: The form to show a human, which may keep original casing.
        sources: Every module claim that produced this entity.
        attributes: Extra structured detail, such as a profile URL.
    """

    type: EntityType
    value: str
    display: str = ""
    sources: list[Source] = field(default_factory=list)
    attributes: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.display:
            self.display = self.value

    @property
    def key(self) -> tuple[EntityType, str]:
        """The identity of this entity, for merging."""
        return (self.type, self.value)

    @property
    def modules(self) -> set[str]:
        """Which modules attested to this entity."""
        return {source.module for source in self.sources}

    @property
    def targets(self) -> set[str]:
        """Which scanned targets this entity was seen from."""
        return {source.target for source in self.sources if source.target}

    @property
    def is_inferred(self) -> bool:
        """Whether *every* source for this entity was a guess.

        One confirmed source is enough to make an entity real; until then it is
        only as good as the guess it came from.
        """
        return bool(self.sources) and all(s.inferred for s in self.sources)

    @property
    def confidence(self) -> float:
        """How well corroborated this entity is, from 0 to 1.

        Corroboration counts *independent* modules, not repeated claims: a
        module that reports the same address six times has still only said it
        once as far as confidence goes. Being seen from more than one starting
        target counts for more again, since that is a genuine cross-check.

        An entity that rests entirely on guesses is capped low however many
        modules repeat it, because repeating a guess does not confirm it.
        """
        if self.is_inferred:
            return INFERRED_CONFIDENCE
        confirmed = {s.module for s in self.sources if not s.inferred}
        score = min(0.5 + 0.2 * (len(confirmed) - 1), 0.9)
        if len(self.targets) > 1:
            score = min(score + 0.1 * (len(self.targets) - 1), 1.0)
        return round(score, 2)

    @property
    def corroboration(self) -> str:
        """A short phrase explaining the confidence, for display."""
        if self.is_inferred:
            return "inferred, unconfirmed"
        modules = len({s.module for s in self.sources if not s.inferred})
        targets = len(self.targets)
        parts = [f"{modules} module{'s' if modules != 1 else ''}"]
        if targets > 1:
            parts.append(f"{targets} starting points")
        return ", ".join(parts)

    def merge(self, other: Entity) -> None:
        """Fold another observation of the same entity into this one."""
        if other.key != self.key:
            raise ValueError(f"cannot merge {other.key} into {self.key}")
        known = set(self.sources)
        self.sources.extend(s for s in other.sources if s not in known)
        for key, value in other.attributes.items():
            self.attributes.setdefault(key, value)

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "display": self.display,
            "confidence": self.confidence,
            "inferred": self.is_inferred,
            "modules": sorted(self.modules),
            "attributes": dict(self.attributes),
            "sources": [
                {
                    "module": s.module,
                    "label": s.label,
                    "detail": s.detail,
                    "scan_id": s.scan_id,
                    "target": s.target,
                    "inferred": s.inferred,
                }
                for s in self.sources
            ],
        }

    @classmethod
    def from_dict(cls, data: Any) -> Entity:
        """Rebuild an entity from an exported profile.

        Only the stated facts are read back. ``confidence``, ``inferred`` and
        ``modules`` are written for whoever reads the file, but they are derived
        from the sources, so recomputing them is what stops an edited file from
        asserting a confidence its provenance does not support.

        The value is re-normalised on the way in. Identity is the normalised
        form, so a hand-written ``Bob@Example.COM`` has to become
        ``bob@example.com`` here or it would sit beside the same address rather
        than merging with it.
        """
        if not isinstance(data, Mapping):
            raise InvestigationError("an entity must be an object")
        try:
            entity_type = EntityType(data.get("type"))
        except ValueError:
            raise InvestigationError(f"unknown entity type {data.get('type')!r}") from None

        value = str(data.get("value") or "").strip()
        if not value:
            raise InvestigationError(f"an entity of type {entity_type.value} has no value")

        raw_sources = data.get("sources") or []
        if not isinstance(raw_sources, list):
            raise InvestigationError(f"the sources of {value!r} must be a list")
        sources = [Source.from_dict(raw) for raw in raw_sources]
        if not sources:
            raise InvestigationError(
                f"{value!r} has no sources; nothing in a profile is unattributable"
            )

        attributes = data.get("attributes") or {}
        if not isinstance(attributes, Mapping):
            raise InvestigationError(f"the attributes of {value!r} must be an object")

        return cls(
            type=entity_type,
            value=normalise(entity_type, value),
            display=str(data.get("display") or value),
            sources=sources,
            attributes={str(k): str(v) for k, v in attributes.items()},
        )


class RelationKind(str, Enum):
    """How two entities are connected."""

    OWNS = "owns"
    USES = "uses"
    MEMBER_OF = "member_of"
    LOCATED_IN = "located_in"
    SAME_AS = "same_as"
    MENTIONED_WITH = "mentioned_with"
    EXPOSED_IN = "exposed_in"

    @property
    def label(self) -> str:
        return {
            RelationKind.OWNS: "owns",
            RelationKind.USES: "uses",
            RelationKind.MEMBER_OF: "member of",
            RelationKind.LOCATED_IN: "located in",
            RelationKind.SAME_AS: "same as",
            RelationKind.MENTIONED_WITH: "seen with",
            RelationKind.EXPOSED_IN: "exposed in",
        }[self]


@dataclass(frozen=True, slots=True)
class Relation:
    """A directed edge between two entities, with the reason for it."""

    source: tuple[EntityType, str]
    target: tuple[EntityType, str]
    kind: RelationKind
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": {"type": self.source[0].value, "value": self.source[1]},
            "target": {"type": self.target[0].value, "value": self.target[1]},
            "kind": self.kind.value,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Any) -> Relation:
        """Rebuild an edge from an exported profile."""
        if not isinstance(data, Mapping):
            raise InvestigationError("a relation must be an object")
        try:
            kind = RelationKind(data.get("kind"))
        except ValueError:
            raise InvestigationError(f"unknown relation kind {data.get('kind')!r}") from None
        return cls(
            source=_endpoint(data.get("source"), "source"),
            target=_endpoint(data.get("target"), "target"),
            kind=kind,
            reason=str(data.get("reason") or ""),
        )


def _endpoint(data: Any, side: str) -> tuple[EntityType, str]:
    """One end of a relation, as the key its entity is stored under."""
    if not isinstance(data, Mapping):
        raise InvestigationError(f"the {side} of a relation must be an object")
    try:
        entity_type = EntityType(data.get("type"))
    except ValueError:
        raise InvestigationError(f"unknown entity type {data.get('type')!r}") from None
    value = str(data.get("value") or "").strip()
    if not value:
        raise InvestigationError(f"the {side} of a relation has no value")
    return (entity_type, normalise(entity_type, value))


# -- normalisation -----------------------------------------------------------

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def normalise(entity_type: EntityType, value: str) -> str:
    """Put a value into the canonical form used for matching.

    Two values that normalise to the same string are treated as the same
    entity, so this function is where correlation is really decided.
    """
    value = value.strip()
    if entity_type in (EntityType.EMAIL, EntityType.DOMAIN, EntityType.USERNAME):
        return value.lower().rstrip(".")
    if entity_type is EntityType.PHONE:
        digits = phone_digits(value)
        return f"+{digits}" if value.lstrip().startswith(("+", "00")) else digits
    if entity_type is EntityType.URL:
        return value.rstrip("/")
    if entity_type is EntityType.PERSON_NAME:
        # Case and punctuation vary between sources; the word sequence does not.
        return " ".join(re.sub(r"[^\w\s'-]", " ", value).lower().split())
    if entity_type is EntityType.ORGANISATION:
        cleaned = re.sub(r"[.,]", " ", value.lower())
        cleaned = re.sub(r"\b(inc|llc|ltd|limited|gmbh|corp|co|plc|sa|bv)\b", " ", cleaned)
        return " ".join(cleaned.split()).lstrip("@")
    return " ".join(value.split())


def is_url(value: str) -> bool:
    return bool(_URL_RE.match(value.strip()))
