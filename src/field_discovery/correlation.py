"""Canonical identity models and deterministic, explainable device correlation."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

_MAC_PLAIN = re.compile(r"^[0-9a-fA-F]{12}$")
_SERIAL_WHITESPACE = re.compile(r"\s+")
_STABLE_KINDS: frozenset[IdentifierKind]


class NormalizationError(ValueError):
    """An identity or observation cannot be represented safely and canonically."""


class IdentifierKind(StrEnum):
    """Supported device identity evidence kinds."""

    MAC = "mac"
    SERIAL = "serial"
    SOURCE_ID = "source_id"
    HOSTNAME = "hostname"
    IPV4 = "ipv4"


_STABLE_KINDS = frozenset({IdentifierKind.MAC, IdentifierKind.SERIAL, IdentifierKind.SOURCE_ID})


def _require_text(value: str, field: str, maximum: int = 512) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        raise NormalizationError(f"{field} must be non-empty and at most {maximum} characters")
    return normalized


def _normalize_mac(value: str) -> str:
    plain = re.sub(r"[:-]", "", value.strip())
    if not _MAC_PLAIN.fullmatch(plain):
        raise NormalizationError("MAC address is invalid")
    return ":".join(plain[index : index + 2].lower() for index in range(0, 12, 2))


def _normalize_hostname(value: str) -> str:
    hostname = _require_text(value, "hostname", 253).rstrip(".").casefold()
    try:
        ascii_name = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NormalizationError("hostname is invalid") from exc
    labels = ascii_name.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        raise NormalizationError("hostname is invalid")
    return ascii_name


def normalize_identifier(kind: IdentifierKind, value: str, namespace: str | None = None) -> str:
    """Normalize one identifier; source IDs remain scoped to their authority."""
    if kind is IdentifierKind.MAC:
        return _normalize_mac(value)
    if kind is IdentifierKind.IPV4:
        try:
            return str(ipaddress.IPv4Address(value.strip()))
        except ipaddress.AddressValueError as exc:
            raise NormalizationError("IPv4 address is invalid") from exc
    if kind is IdentifierKind.HOSTNAME:
        return _normalize_hostname(value)
    if kind is IdentifierKind.SERIAL:
        return _SERIAL_WHITESPACE.sub(" ", _require_text(value, "serial", 256)).casefold()
    if kind is IdentifierKind.SOURCE_ID:
        scope = _require_text(namespace or "", "source ID namespace", 128).casefold()
        identifier = _require_text(value, "source ID", 256).casefold()
        return f"{scope}:{identifier}"
    raise NormalizationError(f"unsupported identifier kind: {kind}")


@dataclass(frozen=True)
class IdentityEvidence:
    """One source-labelled, time-labelled identity claim."""

    kind: IdentifierKind
    value: str
    source: str
    observed_at: datetime
    confidence: float = 1.0
    namespace: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", _require_text(self.source, "source", 128))
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise NormalizationError("observed_at must include a timezone")
        if not 0.0 <= self.confidence <= 1.0:
            raise NormalizationError("confidence must be between 0 and 1")
        object.__setattr__(
            self,
            "value",
            normalize_identifier(self.kind, self.value, self.namespace),
        )
        if self.kind is not IdentifierKind.SOURCE_ID and self.namespace is not None:
            raise NormalizationError("namespace is valid only for source IDs")
        if self.namespace is not None:
            object.__setattr__(self, "namespace", self.namespace.strip().casefold())

    @property
    def key(self) -> str:
        """Stable typed lookup key."""
        return f"{self.kind.value}:{self.value}"


@dataclass(frozen=True)
class InterfaceEvidence:
    """A source observation of one interface belonging to the subject device."""

    interface_key: str
    source: str
    observed_at: datetime
    name: str | None = None
    mac_address: str | None = None
    confidence: float = 1.0

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "interface_key", _require_text(self.interface_key, "interface key")
        )
        object.__setattr__(self, "source", _require_text(self.source, "source", 128))
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise NormalizationError("observed_at must include a timezone")
        if not 0.0 <= self.confidence <= 1.0:
            raise NormalizationError("confidence must be between 0 and 1")
        if self.name is not None:
            object.__setattr__(self, "name", _require_text(self.name, "interface name", 256))
        if self.mac_address is not None:
            object.__setattr__(self, "mac_address", _normalize_mac(self.mac_address))


@dataclass(frozen=True)
class FactEvidence:
    """A bounded canonical fact used to disclose cross-source disagreement."""

    field: str
    value: str
    source: str
    observed_at: datetime
    confidence: float = 1.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "field", _require_text(self.field, "fact field", 128).casefold())
        object.__setattr__(self, "value", _require_text(self.value, "fact value", 1024))
        object.__setattr__(self, "source", _require_text(self.source, "source", 128))
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise NormalizationError("observed_at must include a timezone")
        if not 0.0 <= self.confidence <= 1.0:
            raise NormalizationError("confidence must be between 0 and 1")


@dataclass(frozen=True)
class DeviceObservation:
    """One collector/passive/import subject before correlation."""

    observation_id: str
    source: str
    observed_at: datetime
    identifiers: tuple[IdentityEvidence, ...] = ()
    interfaces: tuple[InterfaceEvidence, ...] = ()
    facts: tuple[FactEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "observation_id", _require_text(self.observation_id, "observation ID")
        )
        object.__setattr__(self, "source", _require_text(self.source, "source", 128))
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise NormalizationError("observed_at must include a timezone")


@dataclass(frozen=True)
class CorrelationDecision:
    """Auditable reason two observations belong to one canonical device."""

    left_observation_id: str
    right_observation_id: str
    evidence_key: str
    confidence: float
    reason: str


@dataclass(frozen=True)
class CorrelationConflict:
    """Conflicting/reused evidence retained rather than silently overwritten."""

    conflict_kind: str
    key: str
    canonical_keys: tuple[str, ...]
    values: tuple[str, ...]
    observation_ids: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class CanonicalDevice:
    """Deterministic correlated representation with all original evidence."""

    canonical_key: str
    observation_ids: tuple[str, ...]
    identifiers: tuple[IdentityEvidence, ...]
    interfaces: tuple[InterfaceEvidence, ...]
    facts: tuple[FactEvidence, ...]
    confidence: float


@dataclass(frozen=True)
class CorrelationResult:
    """Canonical devices plus explicit merge decisions and conflicts."""

    devices: tuple[CanonicalDevice, ...]
    decisions: tuple[CorrelationDecision, ...]
    conflicts: tuple[CorrelationConflict, ...]


def _identity_sort_key(item: IdentityEvidence) -> tuple[str, str, str, str, float]:
    return (
        item.kind.value,
        item.value,
        item.source,
        item.observed_at.isoformat(),
        item.confidence,
    )


def _interface_sort_key(item: InterfaceEvidence) -> tuple[str, str, str, str]:
    return (item.interface_key, item.source, item.observed_at.isoformat(), item.mac_address or "")


def _fact_sort_key(item: FactEvidence) -> tuple[str, str, str, str]:
    return (item.field, item.value.casefold(), item.source, item.observed_at.isoformat())


def _all_identifiers(observation: DeviceObservation) -> tuple[IdentityEvidence, ...]:
    interface_macs = tuple(
        IdentityEvidence(
            IdentifierKind.MAC,
            interface.mac_address,
            interface.source,
            interface.observed_at,
            interface.confidence,
        )
        for interface in observation.interfaces
        if interface.mac_address is not None
    )
    return tuple(sorted((*observation.identifiers, *interface_macs), key=_identity_sort_key))


def _canonical_key(observations: tuple[DeviceObservation, ...]) -> str:
    stable = sorted(
        {
            identifier.key
            for observation in observations
            for identifier in _all_identifiers(observation)
            if identifier.kind in _STABLE_KINDS and identifier.confidence >= 0.8
        }
    )
    seed = stable[0] if stable else f"observation:{observations[0].observation_id}"
    return f"device-{hashlib.sha256(seed.encode()).hexdigest()[:20]}"


def correlate(observations: tuple[DeviceObservation, ...]) -> CorrelationResult:
    """Correlate deterministically using only stable, high-confidence identifiers."""
    ordered = tuple(sorted(observations, key=lambda item: item.observation_id))
    identifiers_by_observation: dict[str, tuple[IdentityEvidence, ...]] = {}
    parent: dict[str, str] = {}
    for observation in ordered:
        if observation.observation_id in parent:
            raise NormalizationError(f"duplicate observation ID: {observation.observation_id}")
        parent[observation.observation_id] = observation.observation_id
        identifiers_by_observation[observation.observation_id] = _all_identifiers(observation)

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        first, second = sorted((left_root, right_root))
        parent[second] = first

    stable_index: dict[str, list[tuple[str, IdentityEvidence]]] = defaultdict(list)
    for observation in ordered:
        for identifier in identifiers_by_observation[observation.observation_id]:
            if identifier.kind in _STABLE_KINDS and identifier.confidence >= 0.8:
                stable_index[identifier.key].append((observation.observation_id, identifier))

    decisions: list[CorrelationDecision] = []
    for evidence_key in sorted(stable_index):
        claims = sorted(stable_index[evidence_key], key=lambda item: item[0])
        first_id, first_evidence = claims[0]
        for other_id, other_evidence in claims[1:]:
            if find(first_id) == find(other_id):
                continue
            confidence = min(first_evidence.confidence, other_evidence.confidence)
            decisions.append(
                CorrelationDecision(
                    first_id,
                    other_id,
                    evidence_key,
                    confidence,
                    "matched stable identifier; hostname and IP were not used as merge evidence",
                )
            )
            union(first_id, other_id)

    groups: dict[str, list[DeviceObservation]] = defaultdict(list)
    for observation in ordered:
        groups[find(observation.observation_id)].append(observation)
    devices: list[CanonicalDevice] = []
    for group in groups.values():
        members = tuple(sorted(group, key=lambda item: item.observation_id))
        canonical_key = _canonical_key(members)
        identifiers = tuple(
            sorted(
                (
                    item
                    for member in members
                    for item in identifiers_by_observation[member.observation_id]
                ),
                key=_identity_sort_key,
            )
        )
        interfaces = tuple(
            sorted(
                (item for member in members for item in member.interfaces), key=_interface_sort_key
            )
        )
        facts = tuple(
            sorted((item for member in members for item in member.facts), key=_fact_sort_key)
        )
        matching_decisions = [
            decision
            for decision in decisions
            if decision.left_observation_id in {member.observation_id for member in members}
            and decision.right_observation_id in {member.observation_id for member in members}
        ]
        stable_confidences = [item.confidence for item in identifiers if item.kind in _STABLE_KINDS]
        confidence = (
            min(decision.confidence for decision in matching_decisions)
            if matching_decisions
            else max(stable_confidences, default=0.5)
        )
        devices.append(
            CanonicalDevice(
                canonical_key,
                tuple(member.observation_id for member in members),
                identifiers,
                interfaces,
                facts,
                confidence,
            )
        )
    devices.sort(key=lambda item: item.canonical_key)

    conflicts = _find_conflicts(tuple(devices))
    return CorrelationResult(
        tuple(devices),
        tuple(sorted(decisions, key=lambda item: (item.evidence_key, item.left_observation_id))),
        conflicts,
    )


def _find_conflicts(devices: tuple[CanonicalDevice, ...]) -> tuple[CorrelationConflict, ...]:
    conflicts: list[CorrelationConflict] = []
    reusable: dict[tuple[IdentifierKind, str], list[tuple[CanonicalDevice, IdentityEvidence]]] = (
        defaultdict(list)
    )
    for device in devices:
        for identifier in device.identifiers:
            if identifier.kind in {IdentifierKind.HOSTNAME, IdentifierKind.IPV4}:
                reusable[(identifier.kind, identifier.value)].append((device, identifier))
    for (kind, value), claims in sorted(
        reusable.items(), key=lambda item: (item[0][0].value, item[0][1])
    ):
        canonical_keys = tuple(sorted({claim[0].canonical_key for claim in claims}))
        if len(canonical_keys) > 1:
            conflicts.append(
                CorrelationConflict(
                    f"reused_{kind.value}",
                    f"{kind.value}:{value}",
                    canonical_keys,
                    (value,),
                    tuple(
                        sorted(
                            {
                                observation_id
                                for claimed_device, _identifier in claims
                                for observation_id in claimed_device.observation_ids
                            }
                        )
                    ),
                    f"{kind.value} appears on multiple devices and was not used to merge them",
                )
            )

    for device in devices:
        serials = tuple(
            sorted(
                {item.value for item in device.identifiers if item.kind is IdentifierKind.SERIAL}
            )
        )
        if len(serials) > 1:
            conflicts.append(
                CorrelationConflict(
                    "conflicting_serial",
                    "serial",
                    (device.canonical_key,),
                    serials,
                    device.observation_ids,
                    "sources reported different serials for a device joined by other "
                    "stable evidence",
                )
            )
        facts_by_field: dict[str, list[FactEvidence]] = defaultdict(list)
        for fact in device.facts:
            facts_by_field[fact.field].append(fact)
        for field, facts in sorted(facts_by_field.items()):
            values = tuple(sorted({fact.value for fact in facts}, key=str.casefold))
            sources = {fact.source for fact in facts}
            if len(values) > 1 and len(sources) > 1:
                conflicts.append(
                    CorrelationConflict(
                        "source_disagreement",
                        field,
                        (device.canonical_key,),
                        values,
                        device.observation_ids,
                        "multiple sources reported different values; all evidence is retained",
                    )
                )
    return tuple(
        sorted(conflicts, key=lambda item: (item.conflict_kind, item.key, item.canonical_keys))
    )
