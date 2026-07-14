"""Deterministic canonical identity and explainable correlation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from field_discovery.correlation import (
    DeviceObservation,
    FactEvidence,
    IdentifierKind,
    IdentityEvidence,
    InterfaceEvidence,
    NormalizationError,
    correlate,
    normalize_identifier,
)

NOW = datetime(2026, 7, 15, 10, 30, tzinfo=UTC)


def identity(
    kind: IdentifierKind,
    value: str,
    *,
    source: str = "fixture-a",
    confidence: float = 1.0,
    namespace: str | None = None,
    observed_at: datetime = NOW,
) -> IdentityEvidence:
    return IdentityEvidence(kind, value, source, observed_at, confidence, namespace)


def observation(
    observation_id: str,
    *identifiers: IdentityEvidence,
    interfaces: tuple[InterfaceEvidence, ...] = (),
    facts: tuple[FactEvidence, ...] = (),
    source: str = "fixture-a",
    observed_at: datetime = NOW,
) -> DeviceObservation:
    return DeviceObservation(
        observation_id, source, observed_at, tuple(identifiers), interfaces, facts
    )


@pytest.mark.parametrize(
    ("kind", "raw", "namespace", "expected"),
    [
        (IdentifierKind.MAC, "AA-BB-CC-DD-EE-FF", None, "aa:bb:cc:dd:ee:ff"),
        (IdentifierKind.IPV4, " 192.0.2.4 ", None, "192.0.2.4"),
        (IdentifierKind.HOSTNAME, "Switch-01.Example.", None, "switch-01.example"),
        (IdentifierKind.HOSTNAME, "münchen.example", None, "xn--mnchen-3ya.example"),
        (IdentifierKind.SERIAL, "  ABC   123 ", None, "abc 123"),
        (IdentifierKind.SOURCE_ID, " Device-9 ", " UniFi Site A ", "unifi site a:device-9"),
    ],
)
def test_identifier_normalization(
    kind: IdentifierKind, raw: str, namespace: str | None, expected: str
) -> None:
    evidence = identity(kind, raw, namespace=namespace)
    assert evidence.value == expected
    assert evidence.key == f"{kind.value}:{expected}"
    assert normalize_identifier(kind, raw, namespace) == expected


@pytest.mark.parametrize(
    ("kind", "raw", "namespace", "message"),
    [
        (IdentifierKind.MAC, "invalid", None, "MAC"),
        (IdentifierKind.IPV4, "999.1.1.1", None, "IPv4"),
        (IdentifierKind.HOSTNAME, "-bad.example", None, "hostname"),
        (IdentifierKind.HOSTNAME, "bad-.example", None, "hostname"),
        (IdentifierKind.HOSTNAME, "bad_label.example", None, "hostname"),
        (IdentifierKind.HOSTNAME, ".", None, "hostname"),
        (IdentifierKind.HOSTNAME, "\ud800.example", None, "hostname"),
        (IdentifierKind.SERIAL, " ", None, "serial"),
        (IdentifierKind.SOURCE_ID, "id", None, "namespace"),
    ],
)
def test_invalid_identifiers_are_rejected(
    kind: IdentifierKind, raw: str, namespace: str | None, message: str
) -> None:
    with pytest.raises(NormalizationError, match=message):
        identity(kind, raw, namespace=namespace)


def test_invalid_identity_metadata_is_rejected() -> None:
    with pytest.raises(NormalizationError, match="source"):
        identity(IdentifierKind.MAC, "001122334455", source="")
    with pytest.raises(NormalizationError, match="timezone"):
        identity(
            IdentifierKind.MAC,
            "001122334455",
            observed_at=datetime(2026, 1, 1),
        )
    with pytest.raises(NormalizationError, match="confidence"):
        identity(IdentifierKind.MAC, "001122334455", confidence=1.1)
    with pytest.raises(NormalizationError, match="namespace"):
        identity(IdentifierKind.MAC, "001122334455", namespace="wrong")
    with pytest.raises(NormalizationError, match="unsupported"):
        normalize_identifier(cast(IdentifierKind, "unknown"), "value")


def test_interface_and_fact_models_normalize_and_validate() -> None:
    minimal = InterfaceEvidence("if-0", "snmp", NOW)
    assert minimal.name is None and minimal.mac_address is None
    interface = InterfaceEvidence(" Gi1/0/1 ", "snmp", NOW, " uplink ", "00-11-22-33-44-55", 0.9)
    assert interface.interface_key == "Gi1/0/1"
    assert interface.name == "uplink"
    assert interface.mac_address == "00:11:22:33:44:55"
    fact = FactEvidence(" Model ", " CX-6000 ", "snmp", NOW, 0.8)
    assert (fact.field, fact.value) == ("model", "CX-6000")

    invalid_interfaces: list[tuple[str, str, datetime, str | None, str | None, float]] = [
        ("", "snmp", NOW, None, None, 1.0),
        ("key", "", NOW, None, None, 1.0),
        ("key", "snmp", datetime(2026, 1, 1), None, None, 1.0),
        ("key", "snmp", NOW, None, None, -0.1),
        ("key", "snmp", NOW, "", None, 1.0),
        ("key", "snmp", NOW, None, "bad", 1.0),
    ]
    for interface_arguments in invalid_interfaces:
        with pytest.raises(NormalizationError):
            InterfaceEvidence(*interface_arguments)

    invalid_facts: list[tuple[str, str, str, datetime, float]] = [
        ("", "value", "snmp", NOW, 1.0),
        ("model", "", "snmp", NOW, 1.0),
        ("model", "value", "", NOW, 1.0),
        ("model", "value", "snmp", datetime(2026, 1, 1), 1.0),
        ("model", "value", "snmp", NOW, 2.0),
    ]
    for fact_arguments in invalid_facts:
        with pytest.raises(NormalizationError):
            FactEvidence(*fact_arguments)


def test_observation_model_validates_contract() -> None:
    assert observation("obs-a").observation_id == "obs-a"
    with pytest.raises(NormalizationError, match="observation ID"):
        observation("")
    with pytest.raises(NormalizationError, match="source"):
        observation("obs", source="")
    with pytest.raises(NormalizationError, match="timezone"):
        observation("obs", observed_at=datetime(2026, 1, 1))


@pytest.mark.parametrize(
    ("alias_kind", "alias_value", "conflict_kind"),
    [
        (IdentifierKind.IPV4, "192.168.1.20", "reused_ipv4"),
        (IdentifierKind.HOSTNAME, "printer.example", "reused_hostname"),
    ],
)
def test_dhcp_ip_and_hostname_reuse_never_merge_devices(
    alias_kind: IdentifierKind, alias_value: str, conflict_kind: str
) -> None:
    earlier = observation(
        "earlier",
        identity(IdentifierKind.MAC, "001122334401"),
        identity(alias_kind, alias_value),
    )
    later = observation(
        "later",
        identity(IdentifierKind.MAC, "001122334402", observed_at=NOW + timedelta(days=1)),
        identity(alias_kind, alias_value, observed_at=NOW + timedelta(days=1)),
        observed_at=NOW + timedelta(days=1),
    )

    result = correlate((later, earlier))

    assert len(result.devices) == 2
    assert result.decisions == ()
    assert [conflict.conflict_kind for conflict in result.conflicts] == [conflict_kind]
    assert result.conflicts[0].observation_ids == ("earlier", "later")
    assert "not used to merge" in result.conflicts[0].explanation


def test_multiple_interfaces_correlate_and_retain_interface_evidence() -> None:
    first = observation(
        "inventory",
        identity(IdentifierKind.SERIAL, "SERIAL-1"),
        interfaces=(
            InterfaceEvidence("if-1", "snmp", NOW, "lan", "001122334411"),
            InterfaceEvidence("if-2", "snmp", NOW, "uplink", "001122334412"),
        ),
    )
    second = observation(
        "neighbor",
        identity(IdentifierKind.MAC, "00:11:22:33:44:12", source="lldp"),
        source="lldp",
    )

    result = correlate((second, first))

    assert len(result.devices) == 1
    assert len(result.devices[0].interfaces) == 2
    assert result.decisions[0].evidence_key == "mac:00:11:22:33:44:12"
    assert "hostname and IP were not used" in result.decisions[0].reason


def test_changing_ip_correlates_only_by_mac_and_keeps_history() -> None:
    first = observation(
        "day-1",
        identity(IdentifierKind.MAC, "001122334421"),
        identity(IdentifierKind.IPV4, "10.0.0.20"),
    )
    second = observation(
        "day-2",
        identity(IdentifierKind.MAC, "001122334421", source="dhcp"),
        identity(IdentifierKind.IPV4, "10.0.0.99", source="dhcp"),
        source="dhcp",
        observed_at=NOW + timedelta(days=1),
    )
    forward = correlate((first, second))
    reverse = correlate((second, first))

    assert forward == reverse
    assert len(forward.devices) == 1
    assert {
        item.value for item in forward.devices[0].identifiers if item.kind is IdentifierKind.IPV4
    } == {"10.0.0.20", "10.0.0.99"}
    assert forward.conflicts == ()


def test_conflicting_serials_and_source_disagreement_remain_auditable() -> None:
    first = observation(
        "snmp",
        identity(IdentifierKind.MAC, "001122334431", source="snmp"),
        identity(IdentifierKind.SERIAL, "SERIAL-A", source="snmp"),
        facts=(FactEvidence("model", "Model A", "snmp", NOW),),
        source="snmp",
    )
    second = observation(
        "ssh",
        identity(IdentifierKind.MAC, "001122334431", source="ssh", confidence=0.9),
        identity(IdentifierKind.SERIAL, "SERIAL-B", source="ssh"),
        facts=(FactEvidence("model", "Model B", "ssh", NOW),),
        source="ssh",
    )

    result = correlate((first, second))

    assert len(result.devices) == 1
    assert result.devices[0].confidence == 0.9
    assert [item.conflict_kind for item in result.conflicts] == [
        "conflicting_serial",
        "source_disagreement",
    ]
    assert result.conflicts[0].values == ("serial-a", "serial-b")
    assert result.conflicts[0].observation_ids == ("snmp", "ssh")
    assert result.conflicts[1].values == ("Model A", "Model B")


def test_source_ids_are_scoped_and_stable_but_low_confidence_is_not_merge_evidence() -> None:
    same_scope = (
        observation("a", identity(IdentifierKind.SOURCE_ID, "42", namespace="controller-a")),
        observation(
            "b",
            identity(
                IdentifierKind.SOURCE_ID,
                "42",
                namespace="controller-a",
                source="controller",
            ),
        ),
    )
    assert len(correlate(same_scope).devices) == 1

    separate_scope = (
        observation("a", identity(IdentifierKind.SOURCE_ID, "42", namespace="controller-a")),
        observation("b", identity(IdentifierKind.SOURCE_ID, "42", namespace="controller-b")),
    )
    assert len(correlate(separate_scope).devices) == 2

    low_confidence = (
        observation("a", identity(IdentifierKind.SERIAL, "same", confidence=0.79)),
        observation("b", identity(IdentifierKind.SERIAL, "same", confidence=0.79)),
    )
    low_result = correlate(low_confidence)
    assert len(low_result.devices) == 2
    assert {device.confidence for device in low_result.devices} == {0.79}


def test_observations_without_stable_identity_stay_separate() -> None:
    first = observation("a", identity(IdentifierKind.HOSTNAME, "same.example"))
    second = observation("b", identity(IdentifierKind.HOSTNAME, "same.example"))
    result = correlate((first, second))
    assert len(result.devices) == 2
    assert {device.confidence for device in result.devices} == {0.5}


def test_duplicate_claims_do_not_create_duplicate_decisions_or_fact_conflict() -> None:
    duplicate_mac = identity(IdentifierKind.MAC, "001122334499")
    first = observation(
        "a",
        duplicate_mac,
        duplicate_mac,
        facts=(
            FactEvidence("model", "A", "same-source", NOW),
            FactEvidence("model", "B", "same-source", NOW),
        ),
    )
    second = observation("b", identity(IdentifierKind.MAC, "001122334499"))
    result = correlate((first, second))
    assert len(result.decisions) == 1
    assert result.conflicts == ()


def test_duplicate_observation_id_is_rejected() -> None:
    with pytest.raises(NormalizationError, match="duplicate observation ID"):
        correlate((observation("duplicate"), observation("duplicate")))


def test_empty_input_is_deterministic() -> None:
    result = correlate(())
    assert result.devices == ()
    assert result.decisions == ()
    assert result.conflicts == ()
