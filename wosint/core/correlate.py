"""Turning findings into a connected picture.

Modules report in isolation: one knows about certificates, another about
Gravatar profiles, a third about phone ranges.  The correlator reads all of
their findings, pulls the entities out, merges the ones that are the same
thing, links them, and works out what is worth scanning next.

The rules here are deliberately explicit rather than clever.  An analyst has to
be able to see why two things were joined, so every entity keeps its sources and
every relation keeps its reason.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .entities import (
    PIVOTABLE,
    Entity,
    EntityType,
    InvestigationError,
    Relation,
    RelationKind,
    Source,
    is_url,
    normalise,
)
from .models import Finding, ModuleResult, Scan
from .targets import Target, TargetType, parse_target

#: Version of the exported profile format. Bumped when a change would stop an
#: older build from reading a file correctly; a file with no version is read as
#: version 1, which is what earlier builds wrote.
FORMAT_VERSION = 1

#: Finding labels that name a person, mapped to the entity type they produce.
LABEL_TYPES: dict[str, EntityType] = {
    "name": EntityType.PERSON_NAME,
    "full name": EntityType.PERSON_NAME,
    "display name": EntityType.PERSON_NAME,
    "probable name": EntityType.PERSON_NAME,
    "registrant org": EntityType.ORGANISATION,
    "organisation": EntityType.ORGANISATION,
    "company": EntityType.ORGANISATION,
    "registrar": EntityType.ORGANISATION,
    "isp": EntityType.ORGANISATION,
    "carrier": EntityType.ORGANISATION,
    "location": EntityType.LOCATION,
    "region": EntityType.LOCATION,
    "country": EntityType.LOCATION,
    "registrant country": EntityType.LOCATION,
    "email": EntityType.EMAIL,
    "public email": EntityType.EMAIL,
    "abuse contact": EntityType.EMAIL,
    "breach": EntityType.BREACH,
    "domain": EntityType.DOMAIN,
    "named in filing by": EntityType.ORGANISATION,
    "officer of": EntityType.ORGANISATION,
    "employer": EntityType.ORGANISATION,
    "educated at": EntityType.ORGANISATION,
    "listed person": EntityType.PERSON_NAME,
    "citizenship": EntityType.LOCATION,
    "place of birth": EntityType.LOCATION,
    "listed country": EntityType.LOCATION,
    "docket": EntityType.DOCUMENT,
    "wikidata item": EntityType.DOCUMENT,
    "official website": EntityType.URL,
    "handle": EntityType.USERNAME,
    "camera serial": EntityType.DOCUMENT,
    "gps position": EntityType.LOCATION,
    "artist": EntityType.PERSON_NAME,
    "owner": EntityType.PERSON_NAME,
    "blog": EntityType.URL,
    "linked site": EntityType.URL,
}

#: Categories whose findings describe accounts on a platform.
ACCOUNT_CATEGORIES = frozenset({"account"})

#: Categories that describe infrastructure rather than a person.
INFRASTRUCTURE_CATEGORIES = frozenset({"dns", "certificate", "network", "registration"})

#: Labels that are metadata about the scan, never entities in their own right.
SKIP_LABELS = frozenset(
    {
        "accounts found",
        "breaches",
        "coverage",
        "rate limit",
        "unchecked sites",
        "attack surface",
        "shared hosting",
        "status",
        "validity",
        "privacy",
        "mail policy",
        "hosting",
        "proxy",
        "account type",
        "provider",
        "local part",
        "digits",
        "e.164",
        "national format",
        "country code",
        "line type",
        "timezone",
        "public repositories",
        "joined",
        "state",
        "sub-address tag",
        "gravatar",
        "avatar",
        # Links we constructed from a finding, rather than found in one.
        "map",
        "docket record",
        "filer profile",
        "officer record",
        "wikidata page",
        "profile url",
    }
)

EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]{2,}")

#: Profile URL shapes whose path carries the account handle. Pulling the handle
#: out is what turns "an account exists" into something that can be scanned in
#: its own right, and it is the step that makes one lead become a chain.
HANDLE_PATTERNS = (
    re.compile(r"^https?://(?:www\.)?github\.com/([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?gitlab\.com/([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?(?:twitter|x)\.com/([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?instagram\.com/([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?reddit\.com/u(?:ser)?/([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?linkedin\.com/in/([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?tiktok\.com/@([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?medium\.com/@([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?keybase\.io/([^/?#]+)/?$", re.I),
    re.compile(r"^https?://t\.me/([^/?#]+)/?$", re.I),
    re.compile(r"^https?://(?:www\.)?pastebin\.com/u/([^/?#]+)/?$", re.I),
)

#: Path segments that are the site's own pages rather than someone's handle.
NOT_HANDLES = frozenset(
    {
        "about",
        "explore",
        "help",
        "home",
        "login",
        "privacy",
        "search",
        "settings",
        "signup",
        "terms",
        "i",
        "share",
        "pricing",
        "features",
    }
)


def handle_from_url(url: str) -> str | None:
    """The account handle in a profile URL, if it is one we recognise.

    Returns ``None`` for a URL whose shape we do not know, rather than guessing
    at a path segment: a wrong handle would send the analyst down a chain of
    scans about somebody else entirely.
    """
    url = url.strip()
    for pattern in HANDLE_PATTERNS:
        match = pattern.match(url)
        if not match:
            continue
        handle = match.group(1).strip().lstrip("@")
        if not handle or handle.lower() in NOT_HANDLES:
            return None
        return handle
    return None


@dataclass(slots=True)
class Pivot:
    """A suggested next scan, with the reason it is worth running."""

    value: str
    type: TargetType
    reason: str
    confidence: float = 0.5
    scanned: bool = False

    def as_target(self) -> Target:
        return parse_target(self.value)

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "type": self.type.value,
            "reason": self.reason,
            "confidence": self.confidence,
            "scanned": self.scanned,
        }


@dataclass(slots=True)
class Investigation:
    """Everything learned about a subject, across however many scans it took.

    This is the object that answers "who is this?": scans go in one at a time
    and the merged entity graph comes out, so scanning a pivot adds to the
    picture instead of replacing it.
    """

    entities: dict[tuple[EntityType, str], Entity] = field(default_factory=dict)
    relations: list[Relation] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)
    _relation_keys: set[tuple] = field(default_factory=set, repr=False)

    # -- ingestion ---------------------------------------------------------

    def add_scan(self, scan: Scan) -> None:
        """Fold a completed scan into the picture."""
        if scan.target.value not in self.scanned:
            self.scanned.append(scan.target.value)

        subject = self._subject_entity(scan.target)
        if subject is not None:
            self.add_entity(subject)

        for result in scan.results.values():
            for entity in extract_entities(result, scan):
                self.add_entity(entity)
                if subject is not None and entity.key != subject.key:
                    self._link(subject, entity, result)

    def add_entity(self, entity: Entity) -> Entity:
        """Merge an entity in, returning the stored one."""
        existing = self.entities.get(entity.key)
        if existing is None:
            self.entities[entity.key] = entity
            return entity
        existing.merge(entity)
        return existing

    def relate(self, source: Entity, target: Entity, kind: RelationKind, reason: str = "") -> None:
        """Record a connection, ignoring duplicates."""
        self._add_relation(Relation(source=source.key, target=target.key, kind=kind, reason=reason))

    # -- reading the picture ------------------------------------------------

    def of_type(self, entity_type: EntityType) -> list[Entity]:
        """Every entity of one type, best corroborated first."""
        found = [e for e in self.entities.values() if e.type is entity_type]
        return sorted(found, key=lambda e: (-e.confidence, e.value))

    @property
    def identifiers(self) -> list[Entity]:
        """Entities strong enough to identify the subject."""
        found = [e for e in self.entities.values() if e.type.is_identifier and not e.is_inferred]
        return sorted(found, key=lambda e: (-e.confidence, e.type.value, e.value))

    def related_to(self, entity: Entity) -> list[tuple[Relation, Entity]]:
        """Everything connected to ``entity``, in either direction."""
        connected = []
        for relation in self.relations:
            if relation.source == entity.key and relation.target in self.entities:
                connected.append((relation, self.entities[relation.target]))
            elif relation.target == entity.key and relation.source in self.entities:
                connected.append((relation, self.entities[relation.source]))
        return connected

    def pivots(self) -> list[Pivot]:
        """Identifiers worth scanning next, most promising first.

        Anything already scanned is marked rather than dropped, so the interface
        can show what has been covered instead of silently hiding it.
        """
        suggestions: list[Pivot] = []
        for entity in self.entities.values():
            target_type = PIVOTABLE.get(entity.type)
            if target_type is None:
                continue

            # Never chain a scan off an unconfirmed guess. Following one would
            # graft whatever it turns up onto this subject's profile, and a
            # guessed handle belonging to a stranger is exactly how two people
            # end up merged into one.
            if entity.is_inferred:
                continue
            try:
                parsed = parse_target(entity.display or entity.value)
            except Exception:
                continue

            # The parsed type has to agree with what we think the entity is.
            # A one-word name such as "Beau" parses as a username, and scanning
            # it as a handle would quietly turn a weak name into a strong
            # identifier for somebody who may be a different person entirely.
            if not _types_agree(parsed.type, target_type):
                continue

            suggestions.append(
                Pivot(
                    value=parsed.value,
                    type=parsed.type,
                    reason=f"{entity.type.label.lower()} from {', '.join(sorted(entity.modules))}",
                    confidence=entity.confidence,
                    scanned=parsed.value in self.scanned,
                )
            )

        suggestions.sort(key=lambda p: (p.scanned, -p.confidence, p.value))
        return suggestions

    def summary(self) -> dict[str, list[Entity]]:
        """The profile, grouped by entity type and ordered for display."""
        order = [
            EntityType.PERSON_NAME,
            EntityType.EMAIL,
            EntityType.USERNAME,
            EntityType.PHONE,
            EntityType.ACCOUNT,
            EntityType.ORGANISATION,
            EntityType.LOCATION,
            EntityType.DOMAIN,
            EntityType.URL,
            EntityType.IP,
            EntityType.BREACH,
            EntityType.DOCUMENT,
        ]
        grouped = {}
        for entity_type in order:
            found = self.of_type(entity_type)
            if found:
                grouped[entity_type] = found
        return grouped

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": FORMAT_VERSION,
            "scanned": list(self.scanned),
            "entities": [e.as_dict() for e in self.entities.values()],
            "relations": [r.as_dict() for r in self.relations],
            "pivots": [p.as_dict() for p in self.pivots()],
        }

    # -- reopening ---------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Any) -> Investigation:
        """Rebuild an investigation from what :meth:`as_dict` wrote.

        Only what was *stated* is read back: entities, their sources, the edges
        between them and which targets have been scanned. Everything derived --
        confidence, whether an entity rests on a guess, and the pivots -- is
        recomputed from the sources here, so a file cannot assert a confidence
        or offer a lead its provenance does not support. That matters because a
        profile is a file on disk that anything can edit before it comes back.

        Raises:
            InvestigationError: If the file is not a profile, or a claim in it
                is unusable.
        """
        if not isinstance(data, Mapping):
            raise InvestigationError("a saved investigation must be a JSON object")

        version = data.get("version", FORMAT_VERSION)
        if not isinstance(version, int) or version > FORMAT_VERSION:
            raise InvestigationError(
                f"this profile is version {version}; this build reads up to {FORMAT_VERSION}"
            )

        entities = data.get("entities")
        if entities is None or not isinstance(entities, list):
            raise InvestigationError("a saved investigation needs an 'entities' list")

        investigation = cls()
        for raw in entities:
            investigation.add_entity(Entity.from_dict(raw))
        for raw in _list(data.get("relations"), "relations"):
            investigation._add_relation(Relation.from_dict(raw))
        for value in _list(data.get("scanned"), "scanned"):
            if not isinstance(value, str):
                raise InvestigationError("'scanned' must list the targets as strings")
            value = value.strip()
            if value and value not in investigation.scanned:
                investigation.scanned.append(value)
        return investigation

    @classmethod
    def from_json(cls, text: str) -> Investigation:
        """Rebuild an investigation from exported JSON text."""
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise InvestigationError(f"not valid JSON: {exc}") from exc
        return cls.from_dict(data)

    def merge(self, other: Investigation) -> None:
        """Fold another investigation into this one.

        Reopening a saved profile and carrying on is the same operation as
        adding a scan: entities with the same identity become one with both
        sets of sources, so a reopened profile keeps growing rather than
        starting again.
        """
        for entity in other.entities.values():
            self.add_entity(entity)
        for relation in other.relations:
            self._add_relation(relation)
        for value in other.scanned:
            if value not in self.scanned:
                self.scanned.append(value)

    # -- internals ---------------------------------------------------------

    def _add_relation(self, relation: Relation) -> None:
        """Store an edge, ignoring one we already have.

        An edge whose ends are not (yet) in the picture is kept rather than
        dropped: a later scan may bring the missing entity in, and
        :meth:`related_to` only ever walks edges whose ends it can resolve.
        """
        key = (relation.source, relation.target, relation.kind)
        if key in self._relation_keys:
            return
        self._relation_keys.add(key)
        self.relations.append(relation)

    def _subject_entity(self, target: Target) -> Entity | None:
        """The entity representing what was scanned."""
        mapping = {
            TargetType.EMAIL: EntityType.EMAIL,
            TargetType.USERNAME: EntityType.USERNAME,
            TargetType.PHONE: EntityType.PHONE,
            TargetType.PERSON: EntityType.PERSON_NAME,
            TargetType.DOMAIN: EntityType.DOMAIN,
            TargetType.URL: EntityType.URL,
            TargetType.IPV4: EntityType.IP,
            TargetType.IPV6: EntityType.IP,
        }
        entity_type = mapping.get(target.type)
        if entity_type is None:
            return None
        return Entity(
            type=entity_type,
            value=normalise(entity_type, target.value),
            display=target.value,
            sources=[
                Source(
                    module="target",
                    label="Scanned directly",
                    target=target.value,
                )
            ],
        )

    def _link(self, subject: Entity, entity: Entity, result: ModuleResult) -> None:
        """Connect a discovered entity back to the subject of the scan."""
        kind = {
            EntityType.ACCOUNT: RelationKind.OWNS,
            EntityType.EMAIL: RelationKind.USES,
            EntityType.PHONE: RelationKind.USES,
            EntityType.USERNAME: RelationKind.USES,
            EntityType.ORGANISATION: RelationKind.MEMBER_OF,
            EntityType.LOCATION: RelationKind.LOCATED_IN,
            EntityType.BREACH: RelationKind.EXPOSED_IN,
            EntityType.PERSON_NAME: RelationKind.SAME_AS,
        }.get(entity.type, RelationKind.MENTIONED_WITH)
        self.relate(subject, entity, kind, reason=f"reported by {result.module}")


def _list(value: Any, name: str) -> list:
    """A list from a saved profile, or a clear error saying which key is wrong."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise InvestigationError(f"{name!r} must be a list")
    return value


def _types_agree(parsed: TargetType, expected: TargetType) -> bool:
    """Whether a parsed target is the kind the entity claimed to be."""
    if parsed is expected:
        return True
    ip_types = {TargetType.IPV4, TargetType.IPV6}
    return parsed in ip_types and expected in ip_types


def extract_entities(result: ModuleResult, scan: Scan) -> list[Entity]:
    """Pull typed entities out of one module's findings."""
    found: list[Entity] = []
    for finding in result.findings:
        found.extend(_entities_from(finding, result, scan))
    return found


def _entities_from(finding: Finding, result: ModuleResult, scan: Scan) -> list[Entity]:
    label = finding.label.strip().lower()
    if label in SKIP_LABELS:
        return []

    source = Source(
        module=result.module,
        label=finding.label,
        detail=finding.detail,
        scan_id=scan.id,
        target=scan.target.value,
        inferred=finding.inferred,
    )
    value = finding.value.strip()
    entities: list[Entity] = []

    entity_type = LABEL_TYPES.get(label)
    # An account finding names a platform in its label and a profile URL in its
    # value, which together identify one account rather than a bare URL.
    if entity_type is None and finding.category in ACCOUNT_CATEGORIES:
        entity_type = EntityType.ACCOUNT
    if entity_type is None:
        entity_type = _infer_type(finding)

    if entity_type is not None and _is_usable(value):
        entities.append(
            Entity(
                type=entity_type,
                value=normalise(entity_type, value),
                display=value,
                sources=[source],
                attributes=(
                    {"platform": finding.label, "url": value}
                    if entity_type is EntityType.ACCOUNT
                    else {}
                ),
            )
        )

        # A recognised profile URL also tells us the handle, which is scannable
        # even though the URL itself is not.
        if entity_type in (EntityType.ACCOUNT, EntityType.URL):
            handle = handle_from_url(value)
            if handle:
                entities.append(
                    Entity(
                        type=EntityType.USERNAME,
                        value=normalise(EntityType.USERNAME, handle),
                        display=handle,
                        sources=[
                            Source(
                                module=result.module,
                                label=f"Handle in {finding.label}",
                                detail=f"from {value}",
                                scan_id=scan.id,
                                target=scan.target.value,
                                inferred=finding.inferred,
                            )
                        ],
                    )
                )

    # An address written inside a bio, a remark or a detail string is still an
    # address, whether or not the finding itself produced an entity.
    if finding.category not in INFRASTRUCTURE_CATEGORIES:
        for match in EMAIL_IN_TEXT.findall(f"{value} {finding.detail}"):
            entities.append(
                Entity(
                    type=EntityType.EMAIL,
                    value=normalise(EntityType.EMAIL, match),
                    display=match,
                    sources=[source],
                )
            )

    return _deduplicate(entities)


def _is_usable(value: str) -> bool:
    """Whether a finding's value names something, rather than reporting absence."""
    return bool(value) and value.lower() not in (
        "unknown",
        "none known",
        "not found",
        "n/a",
    )


def _deduplicate(entities: list[Entity]) -> list[Entity]:
    """Collapse entities that one finding produced twice.

    A finding whose value *is* an address yields it once as the primary entity
    and again from the free-text scan; both carry the same source, so keeping
    one is enough.
    """
    merged: dict[tuple, Entity] = {}
    for entity in entities:
        existing = merged.get(entity.key)
        if existing is None:
            merged[entity.key] = entity
        else:
            existing.merge(entity)
    return list(merged.values())


def _infer_type(finding: Finding) -> EntityType | None:
    """Work out an entity type from the finding's shape when the label is unknown.

    Infrastructure categories are skipped entirely: a certificate's subdomains
    say nothing about a person, and folding them into a profile would bury the
    handful of findings that do.
    """
    value = finding.value.strip()
    if finding.category in INFRASTRUCTURE_CATEGORIES:
        return None
    if finding.category == "search":
        # Search links are starting points we built ourselves, not evidence.
        return None
    if finding.category == "records" and is_url(value):
        # A registry search URL is a place to look, not something found there.
        return None
    if EMAIL_IN_TEXT.fullmatch(value):
        return EntityType.EMAIL
    if is_url(value):
        return EntityType.URL
    return None
