"""Credential-free AD detection fixture and adapter tests."""

from __future__ import annotations

import asyncio
import json
import ssl
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, cast

import dns.exception
import dns.resolver
import ldap3  # type: ignore[import-untyped]
import pytest

from field_discovery.ad_detection import (
    MAX_RECORDS,
    MAX_ROOTDSE_VALUES,
    ROOTDSE_ATTRIBUTES,
    ADDetectionError,
    ADDetectionResult,
    ADDetectionUnreachable,
    ADDetector,
    DetectionIssue,
    DnspythonResolver,
    DomainControllerCandidate,
    Ldap3RootDSEProbe,
    ServiceEvidence,
    SRVRecord,
    _domain_from_dn,
    _normalize_rootdse,
    normalize_domain,
    normalize_site,
    persist_detection,
    repository_service_evidence,
)
from field_discovery.repository import Repository

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests/fixtures/ad/detection.json"
NOW = datetime(2026, 7, 15, 2, 3, 4, tzinfo=UTC)
RANGES = ("192.168.50.0/24",)


class FixtureResolver:
    def __init__(
        self,
        srv: Mapping[str, Sequence[SRVRecord] | BaseException] | None = None,
        addresses: Mapping[str, Sequence[str] | BaseException] | None = None,
    ) -> None:
        self.srv = dict(srv or {})
        self.addresses = dict(addresses or {})
        self.srv_calls: list[str] = []
        self.address_calls: list[str] = []

    async def resolve_srv(self, name: str) -> Sequence[SRVRecord]:
        self.srv_calls.append(name)
        value = self.srv.get(name, ())
        if isinstance(value, BaseException):
            raise value
        return value

    async def resolve_ipv4(self, hostname: str) -> Sequence[str]:
        self.address_calls.append(hostname)
        value = self.addresses.get(hostname, ())
        if isinstance(value, BaseException):
            raise value
        return value


class FixtureRootDSE:
    def __init__(self, values: Mapping[str, Mapping[str, object] | BaseException]) -> None:
        self.values = dict(values)
        self.calls: list[tuple[str, int]] = []
        self.active = 0
        self.maximum = 0

    async def query(self, address: str, port: int) -> Mapping[str, object]:
        self.calls.append((address, port))
        self.active += 1
        self.maximum = max(self.maximum, self.active)
        await asyncio.sleep(0)
        self.active -= 1
        value = self.values.get(address, {})
        if isinstance(value, BaseException):
            raise value
        return value


def fixture() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(FIXTURE.read_text()))


def resolver_from_fixture(value: Mapping[str, Any]) -> FixtureResolver:
    srv = {
        owner: tuple(SRVRecord(**record) for record in records)
        for owner, records in value["srv"].items()
    }
    return FixtureResolver(srv, value["addresses"])


def test_ad_dns_site_and_rootdse_fixture_is_deterministic() -> None:
    value = fixture()
    resolver = resolver_from_fixture(value)
    probe = FixtureRootDSE(value["rootdse"])
    result = asyncio.run(
        ADDetector(resolver, probe, RANGES, concurrency=2).detect(
            value["domains"], sites=value["sites"]
        )
    )
    assert result.domains == ("alpha.example.invalid", "beta.example.invalid")
    assert [(item.domain, item.hostname) for item in result.candidates] == [
        ("alpha.example.invalid", "dc1.alpha.example.invalid"),
        ("alpha.example.invalid", "dc2.alpha.example.invalid"),
        ("beta.example.invalid", "dc1.beta.example.invalid"),
    ]
    first = result.candidates[0]
    assert first.addresses == ("192.168.50.10",)
    assert first.ports == (88, 389)
    assert first.sites == ("Site-A",)
    assert first.sources == (
        "anonymous_rootdse",
        "dns_kerberos_srv",
        "dns_ldap_srv",
        "dns_site_ldap_srv",
    )
    assert first.confidence == 0.98
    assert not result.issues
    assert probe.maximum <= 2
    assert all(address.startswith("192.168.50.") for address, _port in probe.calls)


def test_non_ad_dns_and_rootdse_do_not_create_false_candidate() -> None:
    domain = "nonad.example.invalid"
    resolver = FixtureResolver(
        {f"_kerberos._tcp.{domain}": (SRVRecord(0, 0, 88, f"host.{domain}"),)},
        {f"host.{domain}": ("192.168.50.30",)},
    )
    probe = FixtureRootDSE(
        {
            "192.168.50.30": {
                "defaultNamingContext": ["DC=other,DC=example,DC=invalid"],
                "supportedCapabilities": ["1.3.6.1.4.1.1466.20037"],
            }
        }
    )
    result = asyncio.run(ADDetector(resolver, probe, RANGES).detect([domain]))
    assert result.candidates == ()
    assert result.issues[-1].category == "rootdse_not_ad"


def test_existing_service_evidence_can_be_confirmed_without_srv() -> None:
    domain = "alpha.example.invalid"
    evidence = (
        ServiceEvidence(
            domain,
            f"dc3.{domain}",
            "192.168.50.12",
            636,
            "ldaps",
            "nmap",
        ),
        ServiceEvidence(domain, f"web.{domain}", "192.168.50.13", 443, "https", "nmap"),
    )
    probe = FixtureRootDSE(
        {
            "192.168.50.12": {
                "defaultNamingContext": ["DC=alpha,DC=example,DC=invalid"],
                "supportedCapabilities": ["1.2.840.113556.1.4.800"],
            }
        }
    )
    result = asyncio.run(
        ADDetector(FixtureResolver(), probe, RANGES).detect([domain], service_evidence=evidence)
    )
    assert len(result.candidates) == 1
    assert result.candidates[0].ports == (636,)
    assert result.candidates[0].sources == ("anonymous_rootdse", "nmap")
    assert probe.calls == [("192.168.50.12", 636)]


def test_unreachable_malformed_and_unapproved_inputs_are_isolated() -> None:
    domain = "alpha.example.invalid"
    ldap_owner = f"_ldap._tcp.dc._msdcs.{domain}"
    kerberos_owner = f"_kerberos._tcp.{domain}"
    resolver = FixtureResolver(
        {
            ldap_owner: (
                SRVRecord(0, 0, 389, "outside.other.invalid"),
                SRVRecord(0, 0, 0, f"bad.{domain}"),
                cast(SRVRecord, object()),
                SRVRecord(0, 0, 389, f"dc1.{domain}"),
                SRVRecord(0, 0, 389, f"dc2.{domain}"),
            ),
            kerberos_owner: ADDetectionUnreachable("fixture"),
        },
        {
            f"dc1.{domain}": ("not-an-address", "10.0.0.9"),
            f"dc2.{domain}": ADDetectionError("fixture"),
        },
    )
    probe = FixtureRootDSE({})
    result = asyncio.run(ADDetector(resolver, probe, RANGES).detect([domain]))
    assert [issue.category for issue in result.issues] == [
        "malformed_srv",
        "malformed_srv",
        "malformed_srv",
        "dns_unreachable",
        "malformed_address",
        "target_refused",
        "dns_error",
    ]
    assert len(result.candidates) == 2
    assert probe.calls == []


def test_srv_error_oversize_and_numeric_or_hostname_malformed_are_isolated() -> None:
    domain = "alpha.example.invalid"
    owner = f"_ldap._tcp.dc._msdcs.{domain}"
    resolver = FixtureResolver(
        {
            owner: ADDetectionError("fixture"),
            f"_kerberos._tcp.{domain}": tuple(
                SRVRecord(0, 0, 88, f"dc.{domain}") for _ in range(MAX_RECORDS + 1)
            ),
        }
    )
    result = asyncio.run(ADDetector(resolver, FixtureRootDSE({}), RANGES).detect([domain]))
    assert [issue.category for issue in result.issues] == ["dns_error", "dns_oversized"]

    malformed = FixtureResolver(
        {
            owner: (
                SRVRecord(cast(int, "bad"), 0, 389, f"dc.{domain}"),
                SRVRecord(-1, 0, 389, f"dc.{domain}"),
                SRVRecord(0, 0, 389, f"bad_label.{domain}"),
            )
        }
    )
    result = asyncio.run(ADDetector(malformed, FixtureRootDSE({}), RANGES).detect([domain]))
    assert [issue.category for issue in result.issues] == ["malformed_srv"] * 3


def test_address_lookup_unreachable_is_isolated() -> None:
    domain = "alpha.example.invalid"
    host = f"dc.{domain}"
    resolver = FixtureResolver(
        {f"_ldap._tcp.dc._msdcs.{domain}": (SRVRecord(0, 0, 389, host),)},
        {host: ADDetectionUnreachable("fixture")},
    )
    result = asyncio.run(ADDetector(resolver, FixtureRootDSE({}), RANGES).detect([domain]))
    assert result.issues == (
        DetectionIssue("dns_unreachable", host, "Address lookup was unreachable"),
    )


def test_rootdse_unreachable_malformed_and_outside_domain_are_disclosed() -> None:
    domain = "alpha.example.invalid"
    owner = f"_ldap._tcp.dc._msdcs.{domain}"
    records = tuple(SRVRecord(0, 0, 389, f"dc{index}.{domain}") for index in range(1, 4))
    resolver = FixtureResolver(
        {owner: records},
        {
            f"dc1.{domain}": ("192.168.50.1",),
            f"dc2.{domain}": ("192.168.50.2",),
            f"dc3.{domain}": ("192.168.50.3",),
        },
    )
    probe = FixtureRootDSE(
        {
            "192.168.50.1": ADDetectionUnreachable("fixture"),
            "192.168.50.2": {"unexpected": ["value"]},
            "192.168.50.3": {
                "defaultNamingContext": ["DC=other,DC=invalid"],
                "supportedCapabilities": ["1.2.840.113556.1.4.800"],
            },
        }
    )
    result = asyncio.run(ADDetector(resolver, probe, RANGES).detect([domain]))
    assert [issue.category for issue in result.issues] == [
        "rootdse_unreachable",
        "rootdse_malformed",
        "rootdse_not_ad",
    ]
    assert len(result.candidates) == 3
    assert all(candidate.confidence == 0.8 for candidate in result.candidates)


@pytest.mark.parametrize(
    "value",
    ["", "localhost", "_ldap.example.invalid", "bad..example.invalid", "*.example.invalid"],
)
def test_domain_validation_rejects_unqualified_or_unsafe_values(value: str) -> None:
    with pytest.raises(ADDetectionError, match="domain"):
        normalize_domain(value)
    with pytest.raises(ADDetectionError):
        normalize_domain(cast(str, None))


@pytest.mark.parametrize("value", ["", " bad", "x" * 64, "site/one"])
def test_site_validation_is_bounded(value: str) -> None:
    with pytest.raises(ADDetectionError, match="site"):
        normalize_site(value)
    with pytest.raises(ADDetectionError):
        normalize_site(cast(str, None))


def test_detector_bounds_domain_site_and_concurrency() -> None:
    with pytest.raises(ValueError, match="concurrency"):
        ADDetector(FixtureResolver(), FixtureRootDSE({}), RANGES, concurrency=0)
    with pytest.raises(ValueError, match="concurrency"):
        ADDetector(FixtureResolver(), FixtureRootDSE({}), RANGES, concurrency=17)
    detector = ADDetector(FixtureResolver(), FixtureRootDSE({}), RANGES)
    with pytest.raises(ADDetectionError, match="1 to 16"):
        asyncio.run(detector.detect([]))
    with pytest.raises(ADDetectionError, match="1 to 16"):
        asyncio.run(detector.detect([f"domain{index}.example.invalid" for index in range(17)]))
    with pytest.raises(ADDetectionError, match="32 sites"):
        asyncio.run(
            detector.detect(
                ["alpha.example.invalid"], sites=[f"Site{index}" for index in range(33)]
            )
        )


def test_stored_evidence_malformed_and_oversized_is_bounded() -> None:
    domain = "alpha.example.invalid"
    malformed = [
        ServiceEvidence("other.example.invalid", f"dc.{domain}", "192.168.50.1", 389, "ldap"),
        ServiceEvidence(domain, f"dc.{domain}", "bad", 389, "ldap"),
        cast(ServiceEvidence, object()),
    ]
    oversized = tuple(
        malformed
        + [ServiceEvidence(domain, f"web.{domain}", "192.168.50.2", 443, "https")] * MAX_RECORDS
    )
    result = asyncio.run(
        ADDetector(FixtureResolver(), FixtureRootDSE({}), RANGES).detect(
            [domain], service_evidence=oversized
        )
    )
    assert result.candidates == ()
    assert result.issues[0].category == "service_oversized"
    assert any(issue.category == "malformed_service" for issue in result.issues)


def test_rootdse_normalization_and_dn_validation() -> None:
    assert _domain_from_dn("DC=Alpha, DC=Example, DC=Invalid") == "alpha.example.invalid"
    assert _domain_from_dn("OU=Servers") is None
    assert _domain_from_dn("DC=bad value,DC=invalid") is None
    with pytest.raises(ADDetectionError, match="outside"):
        _normalize_rootdse({"unknown": "value"})
    with pytest.raises(ADDetectionError, match="malformed"):
        _normalize_rootdse({"namingContexts": ["x"] * (MAX_ROOTDSE_VALUES + 1)})
    with pytest.raises(ADDetectionError, match="malformed"):
        _normalize_rootdse({"dnsHostName": 3})
    normalized = _normalize_rootdse({"dnsHostName": "x" * 2048})
    assert len(normalized["dnsHostName"][0]) == 1024


def repository(tmp_path: Path) -> tuple[Repository, int]:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    repo = Repository.open(root / "discovery.db", data_root=root)
    deployment = repo.upsert_deployment("fixture", "Fixture", NOW.isoformat())
    return repo, deployment


def test_repository_service_evidence_and_detection_persistence(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    device = repo.upsert_device(deployment, "fixture-device", NOW.isoformat())
    repo.connection.execute(
        "INSERT INTO device_aliases"
        "(device_id,alias_kind,alias_value,confidence,source,observed_at) "
        "VALUES (?, 'hostname', ?, 0.9, 'nmap', ?)",
        (device, "dc1.alpha.example.invalid", NOW.isoformat()),
    )
    repo.connection.execute(
        "INSERT INTO address_assignments"
        "(device_id,address_kind,address,first_seen_at,last_seen_at,source,observed_at) "
        "VALUES (?, 'ipv4', '192.168.50.10', ?, ?, 'nmap', ?)",
        (device, NOW.isoformat(), NOW.isoformat(), NOW.isoformat()),
    )
    repo.connection.execute(
        "INSERT INTO services(device_id,transport,port,service_name,state,source,observed_at) "
        "VALUES (?, 'tcp', 389, 'ldap', 'open', 'nmap', ?)",
        (device, NOW.isoformat()),
    )
    evidence = repository_service_evidence(repo, deployment, ["alpha.example.invalid"])
    assert evidence == (
        ServiceEvidence(
            "alpha.example.invalid",
            "dc1.alpha.example.invalid",
            "192.168.50.10",
            389,
            "ldap",
            "nmap",
        ),
    )
    candidate = DomainControllerCandidate(
        "alpha.example.invalid",
        "dc1.alpha.example.invalid",
        ("192.168.50.10",),
        (389,),
        (),
        ("dns_ldap_srv",),
        {},
        0.8,
    )
    result = ADDetectionResult(
        ("alpha.example.invalid",),
        (candidate,),
        (DetectionIssue("dns_error", "owner", "DNS query failed safely"),),
    )
    assert persist_detection(repo, deployment, result, observed_at=NOW) == 1
    facts = [
        row[0] for row in repo.connection.execute("SELECT fact_type FROM observations ORDER BY id")
    ]
    assert facts == ["ad.detection", "dns_error"]
    repo.close()


def test_repository_evidence_skips_missing_or_unapproved_hostname(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    for index, hostname in enumerate((None, "dc.other.invalid"), start=1):
        device = repo.upsert_device(deployment, f"device-{index}", NOW.isoformat())
        if hostname is not None:
            repo.connection.execute(
                "INSERT INTO device_aliases"
                "(device_id,alias_kind,alias_value,confidence,source,observed_at) "
                "VALUES (?, 'hostname', ?, 0.9, 'nmap', ?)",
                (device, hostname, NOW.isoformat()),
            )
        repo.connection.execute(
            "INSERT INTO services(device_id,transport,port,service_name,state,source,observed_at) "
            "VALUES (?, 'tcp', 389, 'ldap', 'open', 'nmap', ?)",
            (device, NOW.isoformat()),
        )
        if hostname is not None:
            repo.connection.execute(
                "INSERT INTO address_assignments"
                "(device_id,address_kind,address,first_seen_at,last_seen_at,source,observed_at) "
                "VALUES (?, 'ipv4', '192.168.50.30', ?, ?, 'nmap', ?)",
                (device, NOW.isoformat(), NOW.isoformat(), NOW.isoformat()),
            )
    assert repository_service_evidence(repo, deployment, ["alpha.example.invalid"]) == ()
    repo.close()


class FakeDNSAnswer:
    def __init__(self, records: Sequence[object], *, has_rrset: bool = True) -> None:
        self.records = records
        self.rrset = object() if has_rrset else None

    def __iter__(self) -> Any:
        return iter(self.records)


class FakeSRV:
    priority = 0
    weight = 100
    port = 389
    target = "dc1.alpha.example.invalid."


class FakeA:
    address = "192.168.50.10"


class FakeDNSResolver:
    action: object = FakeDNSAnswer(())
    calls: ClassVar[list[tuple[object, ...]]] = []

    def resolve(self, *args: object, **kwargs: object) -> object:
        self.calls.append((*args, kwargs))
        if isinstance(self.action, BaseException):
            raise self.action
        return self.action


def test_dnspython_adapter_returns_bounded_srv_and_a_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDNSResolver()
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: fake)
    resolver = DnspythonResolver(2)
    fake.action = FakeDNSAnswer((FakeSRV(),))
    assert asyncio.run(resolver.resolve_srv("_ldap._tcp.example.invalid")) == (
        SRVRecord(0, 100, 389, "dc1.alpha.example.invalid."),
    )
    fake.action = FakeDNSAnswer((FakeA(),))
    assert asyncio.run(resolver.resolve_ipv4("dc1.alpha.example.invalid")) == ("192.168.50.10",)
    assert cast(dict[str, object], fake.calls[-1][-1])["search"] is False

    fake.action = FakeDNSAnswer((), has_rrset=False)
    assert resolver._resolve_srv_sync("none.example.invalid") == ()
    assert resolver._resolve_ipv4_sync("none.example.invalid") == ()
    with pytest.raises(ValueError, match="positive"):
        DnspythonResolver(0)


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (dns.resolver.NXDOMAIN(), None),  # type: ignore[no-untyped-call]
        (dns.resolver.NoAnswer(), None),  # type: ignore[no-untyped-call]
        (dns.exception.Timeout(), ADDetectionUnreachable),  # type: ignore[no-untyped-call]
        (dns.exception.DNSException(), ADDetectionError),  # type: ignore[no-untyped-call]
    ],
)
def test_dnspython_srv_failure_mapping(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    expected: type[BaseException] | None,
) -> None:
    fake = FakeDNSResolver()
    fake.action = failure
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: fake)
    resolver = DnspythonResolver()
    if expected is None:
        assert resolver._resolve_srv_sync("owner.example.invalid") == ()
    else:
        with pytest.raises(expected):
            resolver._resolve_srv_sync("owner.example.invalid")


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (dns.resolver.NXDOMAIN(), None),  # type: ignore[no-untyped-call]
        (dns.resolver.NoAnswer(), None),  # type: ignore[no-untyped-call]
        (dns.exception.Timeout(), ADDetectionUnreachable),  # type: ignore[no-untyped-call]
        (dns.exception.DNSException(), ADDetectionError),  # type: ignore[no-untyped-call]
    ],
)
def test_dnspython_address_failure_mapping(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    expected: type[BaseException] | None,
) -> None:
    fake = FakeDNSResolver()
    fake.action = failure
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: fake)
    resolver = DnspythonResolver()
    if expected is None:
        assert resolver._resolve_ipv4_sync("host.example.invalid") == ()
    else:
        with pytest.raises(expected):
            resolver._resolve_ipv4_sync("host.example.invalid")


def test_dnspython_adapter_rejects_oversized_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDNSResolver()
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: fake)
    resolver = DnspythonResolver()
    fake.action = FakeDNSAnswer(tuple(FakeSRV() for _ in range(MAX_RECORDS + 1)))
    with pytest.raises(ADDetectionError, match="record limit"):
        resolver._resolve_srv_sync("owner.example.invalid")
    fake.action = FakeDNSAnswer(tuple(FakeA() for _ in range(MAX_RECORDS + 1)))
    with pytest.raises(ADDetectionError, match="record limit"):
        resolver._resolve_ipv4_sync("host.example.invalid")


class FakeLDAPEntry:
    entry_attributes_as_dict: ClassVar[dict[str, list[str]]] = {
        "defaultNamingContext": ["DC=alpha,DC=example,DC=invalid"],
        "supportedCapabilities": ["1.2.840.113556.1.4.800"],
    }


class FakeLDAPConnection:
    search_result = True
    entries_result: ClassVar[list[object]] = [FakeLDAPEntry()]
    kwargs: ClassVar[dict[str, object]] = {}
    search_args: tuple[object, ...] = ()
    unbound = False

    def __init__(self, _server: object, **kwargs: object) -> None:
        type(self).kwargs = kwargs
        self.entries = list(type(self).entries_result)

    def search(self, *args: object, **kwargs: object) -> bool:
        type(self).search_args = (*args, kwargs)
        return type(self).search_result

    def unbind(self) -> None:
        type(self).unbound = True


def test_ldap3_rootdse_adapter_is_anonymous_base_scope_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    servers: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def server(*args: object, **kwargs: object) -> object:
        servers.append((args, kwargs))
        return object()

    tls_calls: list[object] = []

    def tls(*, validate: object) -> object:
        tls_calls.append(validate)
        return "strict-tls"

    monkeypatch.setattr(ldap3, "Server", server)
    monkeypatch.setattr(ldap3, "Tls", tls)
    monkeypatch.setattr(ldap3, "Connection", FakeLDAPConnection)
    FakeLDAPConnection.search_result = True
    FakeLDAPConnection.entries_result = [FakeLDAPEntry()]
    FakeLDAPConnection.unbound = False
    probe = Ldap3RootDSEProbe(2)
    result = asyncio.run(probe.query("192.168.50.10", 636))
    assert result["defaultNamingContext"] == ["DC=alpha,DC=example,DC=invalid"]
    assert servers[0][1]["use_ssl"] is True
    assert servers[0][1]["tls"] == "strict-tls"
    assert tls_calls == [ssl.CERT_REQUIRED]
    assert FakeLDAPConnection.kwargs["authentication"] == ldap3.ANONYMOUS
    assert "user" not in FakeLDAPConnection.kwargs
    search_kwargs = cast(dict[str, object], FakeLDAPConnection.search_args[-1])
    assert FakeLDAPConnection.search_args[:2] == ("", "(objectClass=*)")
    assert search_kwargs["search_scope"] == ldap3.BASE
    assert search_kwargs["attributes"] == list(ROOTDSE_ATTRIBUTES)
    assert FakeLDAPConnection.unbound
    with pytest.raises(ValueError, match="positive"):
        Ldap3RootDSEProbe(0)


def test_ldap3_rootdse_rejected_and_unexpected_entry_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ldap3, "Server", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(ldap3, "Connection", FakeLDAPConnection)
    probe = Ldap3RootDSEProbe()
    FakeLDAPConnection.search_result = False
    with pytest.raises(ADDetectionError, match="rejected"):
        probe._query_sync("192.168.50.10", 389)
    FakeLDAPConnection.search_result = True
    FakeLDAPConnection.entries_result = []
    with pytest.raises(ADDetectionError, match="entry count"):
        probe._query_sync("192.168.50.10", 389)
    FakeLDAPConnection.entries_result = [FakeLDAPEntry()]


class LDAPSocketOpenError(Exception):
    pass


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (LDAPSocketOpenError(), ADDetectionUnreachable),
        (RuntimeError(), ADDetectionError),
    ],
)
def test_ldap3_rootdse_connection_failure_mapping(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    expected: type[BaseException],
) -> None:
    monkeypatch.setattr(ldap3, "Server", lambda *_args, **_kwargs: object())

    def connection(*_args: object, **_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(ldap3, "Connection", connection)
    with pytest.raises(expected):
        Ldap3RootDSEProbe()._query_sync("192.168.50.10", 389)
