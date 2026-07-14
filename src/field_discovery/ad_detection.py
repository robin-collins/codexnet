"""Credential-free Active Directory detection from bounded, approved evidence."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import dns.exception
import dns.resolver
import ldap3  # type: ignore[import-untyped]

from field_discovery.collectors import TargetApprovalError, approve_target
from field_discovery.repository import Repository

MAX_DOMAINS = 16
MAX_SITES = 32
MAX_RECORDS = 512
MAX_ROOTDSE_VALUES = 128
AD_PORTS = frozenset({53, 88, 389, 445, 464, 636, 3268, 3269})
AD_SERVICE_NAMES = frozenset(
    {"domain", "dns", "kerberos", "ldap", "ldaps", "microsoft-ds", "globalcatldap"}
)
ROOTDSE_ATTRIBUTES = (
    "defaultNamingContext",
    "rootDomainNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "dnsHostName",
    "namingContexts",
    "supportedCapabilities",
)
AD_CAPABILITY_OIDS = frozenset(
    {
        "1.2.840.113556.1.4.800",
        "1.2.840.113556.1.4.1670",
        "1.2.840.113556.1.4.1791",
    }
)
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
_SITE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")


class ADDetectionError(RuntimeError):
    """A bounded, secret-free AD detection failure."""


class ADDetectionUnreachable(ADDetectionError):
    """A DNS or RootDSE endpoint did not respond within its bound."""


@dataclass(frozen=True, order=True)
class SRVRecord:
    """One normalized DNS SRV answer."""

    priority: int
    weight: int
    port: int
    target: str


@dataclass(frozen=True)
class ServiceEvidence:
    """An existing, non-secret service observation that may identify a DC."""

    domain: str
    host: str
    address: str
    port: int
    service: str
    source: str = "existing_service"


@dataclass(frozen=True)
class DetectionIssue:
    """A non-fatal, secret-free limitation."""

    category: str
    subject: str
    detail: str


@dataclass(frozen=True)
class DomainControllerCandidate:
    """An explainable candidate supported by DNS and/or RootDSE evidence."""

    domain: str
    hostname: str
    addresses: tuple[str, ...]
    ports: tuple[int, ...]
    sites: tuple[str, ...]
    sources: tuple[str, ...]
    rootdse: Mapping[str, tuple[str, ...]]
    confidence: float


@dataclass(frozen=True)
class ADDetectionResult:
    """Deterministic detection output for explicitly approved domains."""

    domains: tuple[str, ...]
    candidates: tuple[DomainControllerCandidate, ...]
    issues: tuple[DetectionIssue, ...]


class DNSResolver(Protocol):
    """Bounded DNS operations used by detection."""

    async def resolve_srv(self, name: str) -> Sequence[SRVRecord]:
        """Resolve one exact SRV owner name."""

    async def resolve_ipv4(self, hostname: str) -> Sequence[str]:
        """Resolve one candidate hostname to IPv4 targets."""


class RootDSEProbe(Protocol):
    """Anonymous RootDSE base query; credentials are intentionally absent."""

    async def query(self, address: str, port: int) -> Mapping[str, object]:
        """Read only the fixed RootDSE attribute set from one approved IP."""


def normalize_domain(value: str) -> str:
    """Return a strict ASCII DNS domain with no wildcard or SRV labels."""
    if not isinstance(value, str):
        raise ADDetectionError("approved AD domain must be a string")
    domain = value.strip().rstrip(".").casefold()
    if not domain or len(domain) > 253 or "." not in domain:
        raise ADDetectionError("approved AD domain must be a qualified DNS name")
    labels = domain.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise ADDetectionError("approved AD domain contains an invalid DNS label")
    return domain


def normalize_site(value: str) -> str:
    """Accept one bounded AD site token for the site-specific SRV owner."""
    if not isinstance(value, str) or not _SITE.fullmatch(value):
        raise ADDetectionError("AD site must be a bounded DNS-safe name")
    return value


def _hostname(value: str, domain: str) -> str:
    host = value.strip().rstrip(".").casefold()
    if host == domain or not host.endswith(f".{domain}"):
        raise ADDetectionError("SRV target is outside the approved AD domain")
    for label in host.split("."):
        if not _LABEL.fullmatch(label):
            raise ADDetectionError("SRV target contains an invalid DNS label")
    return host


def _validate_srv(record: SRVRecord, domain: str) -> SRVRecord:
    if not all(isinstance(value, int) for value in (record.priority, record.weight, record.port)):
        raise ADDetectionError("SRV record numeric fields are malformed")
    if not 0 <= record.priority <= 65535 or not 0 <= record.weight <= 65535:
        raise ADDetectionError("SRV record priority or weight is out of range")
    if not 1 <= record.port <= 65535:
        raise ADDetectionError("SRV record port is out of range")
    return SRVRecord(record.priority, record.weight, record.port, _hostname(record.target, domain))


def _domain_from_dn(value: str) -> str | None:
    labels: list[str] = []
    for component in value.split(","):
        name, separator, item = component.strip().partition("=")
        if separator and name.casefold() == "dc" and _LABEL.fullmatch(item):
            labels.append(item.casefold())
        elif separator and name.casefold() == "dc":
            return None
    return ".".join(labels) if labels else None


def _normalize_rootdse(value: Mapping[str, object]) -> dict[str, tuple[str, ...]]:
    unknown = set(value) - set(ROOTDSE_ATTRIBUTES)
    if unknown:
        raise ADDetectionError("RootDSE returned attributes outside the fixed allowlist")
    normalized: dict[str, tuple[str, ...]] = {}
    for attribute in ROOTDSE_ATTRIBUTES:
        raw = value.get(attribute)
        if raw is None:
            continue
        items = raw if isinstance(raw, list | tuple) else (raw,)
        if len(items) > MAX_ROOTDSE_VALUES or not all(isinstance(item, str) for item in items):
            raise ADDetectionError("RootDSE attribute values are malformed or oversized")
        normalized[attribute] = tuple(str(item)[:1024] for item in items)
    return normalized


def _rootdse_confirms_ad(rootdse: Mapping[str, tuple[str, ...]], domain: str) -> bool:
    naming = rootdse.get("defaultNamingContext", ())
    naming_domain = _domain_from_dn(naming[0]) if naming else None
    capabilities = set(rootdse.get("supportedCapabilities", ()))
    return naming_domain == domain and bool(capabilities & AD_CAPABILITY_OIDS)


class DnspythonResolver:
    """Production DNS adapter with explicit lifetime and no search-list expansion."""

    def __init__(self, timeout_seconds: float = 3.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("DNS timeout must be positive")
        self.timeout_seconds = timeout_seconds

    async def resolve_srv(self, name: str) -> Sequence[SRVRecord]:
        return await asyncio.to_thread(self._resolve_srv_sync, name)

    def _resolve_srv_sync(self, name: str) -> tuple[SRVRecord, ...]:
        resolver = dns.resolver.Resolver()
        try:
            answer = resolver.resolve(
                name, "SRV", search=False, lifetime=self.timeout_seconds, raise_on_no_answer=False
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ()
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
            raise ADDetectionUnreachable("DNS SRV query timed out") from exc
        except dns.exception.DNSException as exc:
            raise ADDetectionError("DNS SRV query failed") from exc
        if answer.rrset is None:
            return ()
        records = tuple(
            SRVRecord(int(item.priority), int(item.weight), int(item.port), str(item.target))
            for item in answer
        )
        if len(records) > MAX_RECORDS:
            raise ADDetectionError("DNS SRV answer exceeds the record limit")
        return records

    async def resolve_ipv4(self, hostname: str) -> Sequence[str]:
        return await asyncio.to_thread(self._resolve_ipv4_sync, hostname)

    def _resolve_ipv4_sync(self, hostname: str) -> tuple[str, ...]:
        resolver = dns.resolver.Resolver()
        try:
            answer = resolver.resolve(
                hostname, "A", search=False, lifetime=self.timeout_seconds, raise_on_no_answer=False
            )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ()
        except (dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
            raise ADDetectionUnreachable("DNS address query timed out") from exc
        except dns.exception.DNSException as exc:
            raise ADDetectionError("DNS address query failed") from exc
        if answer.rrset is None:
            return ()
        addresses = tuple(str(item.address) for item in answer)
        if len(addresses) > MAX_RECORDS:
            raise ADDetectionError("DNS address answer exceeds the record limit")
        return addresses


class Ldap3RootDSEProbe:
    """Anonymous, base-scope RootDSE adapter with no credential parameters."""

    def __init__(self, timeout_seconds: float = 3.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("RootDSE timeout must be positive")
        self.timeout_seconds = timeout_seconds

    async def query(self, address: str, port: int) -> Mapping[str, object]:
        return await asyncio.to_thread(self._query_sync, address, port)

    def _query_sync(self, address: str, port: int) -> Mapping[str, object]:
        server = ldap3.Server(
            address,
            port=port,
            use_ssl=port == 636,
            tls=ldap3.Tls(validate=ssl.CERT_REQUIRED) if port == 636 else None,
            connect_timeout=self.timeout_seconds,
            get_info=ldap3.NONE,
        )
        connection: Any = None
        try:
            connection = ldap3.Connection(
                server,
                authentication=ldap3.ANONYMOUS,
                receive_timeout=self.timeout_seconds,
                auto_bind=True,
                raise_exceptions=True,
            )
            if not connection.search(
                "", "(objectClass=*)", search_scope=ldap3.BASE, attributes=list(ROOTDSE_ATTRIBUTES)
            ):
                raise ADDetectionError("anonymous RootDSE base query was rejected")
            if len(connection.entries) != 1:
                raise ADDetectionError("RootDSE query returned an unexpected entry count")
            return cast(Mapping[str, object], connection.entries[0].entry_attributes_as_dict)
        except ADDetectionError:
            raise
        except Exception as exc:
            name = type(exc).__name__.casefold()
            if "timeout" in name or "socket" in name or "communication" in name:
                raise ADDetectionUnreachable("RootDSE target was unreachable") from exc
            raise ADDetectionError("anonymous RootDSE query failed") from exc
        finally:
            if connection is not None:
                connection.unbind()


@dataclass
class _CandidateState:
    addresses: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    sites: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    ldap_srv: bool = False
    rootdse: dict[str, tuple[str, ...]] = field(default_factory=dict)
    rootdse_confirmed: bool = False


class ADDetector:
    """Correlate credential-free DNS, stored service, and approved RootDSE evidence."""

    def __init__(
        self,
        resolver: DNSResolver,
        rootdse_probe: RootDSEProbe,
        approved_ranges: Sequence[str],
        *,
        concurrency: int = 4,
    ) -> None:
        if concurrency < 1 or concurrency > 16:
            raise ValueError("AD detection concurrency must be from 1 to 16")
        self.resolver = resolver
        self.rootdse_probe = rootdse_probe
        self.approved_ranges = tuple(approved_ranges)
        self.concurrency = concurrency

    async def detect(
        self,
        domains: Sequence[str],
        *,
        sites: Sequence[str] = (),
        service_evidence: Sequence[ServiceEvidence] = (),
    ) -> ADDetectionResult:
        approved_domains = tuple(sorted({normalize_domain(value) for value in domains}))
        approved_sites = tuple(sorted({normalize_site(value) for value in sites}))
        if not approved_domains or len(approved_domains) > MAX_DOMAINS:
            raise ADDetectionError("AD detection requires 1 to 16 approved domains")
        if len(approved_sites) > MAX_SITES:
            raise ADDetectionError("AD detection accepts at most 32 sites")
        states: dict[tuple[str, str], _CandidateState] = defaultdict(_CandidateState)
        issues: list[DetectionIssue] = []
        for domain in approved_domains:
            await self._dns_evidence(domain, approved_sites, states, issues)
        self._stored_evidence(approved_domains, service_evidence, states, issues)
        await self._resolve_and_probe(states, issues)
        candidates = tuple(
            DomainControllerCandidate(
                domain=domain,
                hostname=host,
                addresses=tuple(sorted(state.addresses, key=ipaddress.ip_address)),
                ports=tuple(sorted(state.ports)),
                sites=tuple(sorted(state.sites)),
                sources=tuple(sorted(state.sources)),
                rootdse=dict(sorted(state.rootdse.items())),
                confidence=0.98 if state.rootdse_confirmed else 0.8,
            )
            for (domain, host), state in sorted(states.items())
            if state.ldap_srv or state.rootdse_confirmed
        )
        return ADDetectionResult(approved_domains, candidates, tuple(issues))

    async def _dns_evidence(
        self,
        domain: str,
        sites: Sequence[str],
        states: dict[tuple[str, str], _CandidateState],
        issues: list[DetectionIssue],
    ) -> None:
        queries: list[tuple[str, str, str | None, bool]] = [
            (f"_ldap._tcp.dc._msdcs.{domain}", "dns_ldap_srv", None, True),
            (f"_kerberos._tcp.{domain}", "dns_kerberos_srv", None, False),
        ]
        queries.extend(
            (
                f"_ldap._tcp.{site}._sites.dc._msdcs.{domain}",
                "dns_site_ldap_srv",
                site,
                True,
            )
            for site in sites
        )
        for owner, source, site, is_ldap in queries:
            try:
                records = await self.resolver.resolve_srv(owner)
            except ADDetectionUnreachable:
                issues.append(DetectionIssue("dns_unreachable", owner, "DNS query was unreachable"))
                continue
            except ADDetectionError:
                issues.append(DetectionIssue("dns_error", owner, "DNS query failed safely"))
                continue
            if len(records) > MAX_RECORDS:
                issues.append(
                    DetectionIssue("dns_oversized", owner, "DNS answer exceeded the record limit")
                )
                continue
            for record in records:
                try:
                    normalized = _validate_srv(record, domain)
                except (ADDetectionError, AttributeError):
                    issues.append(
                        DetectionIssue("malformed_srv", owner, "Malformed SRV record was ignored")
                    )
                    continue
                state = states[(domain, normalized.target)]
                state.ports.add(normalized.port)
                state.sources.add(source)
                state.ldap_srv = state.ldap_srv or is_ldap
                if site is not None:
                    state.sites.add(site)

    @staticmethod
    def _stored_evidence(
        domains: Sequence[str],
        evidence: Sequence[ServiceEvidence],
        states: dict[tuple[str, str], _CandidateState],
        issues: list[DetectionIssue],
    ) -> None:
        if len(evidence) > MAX_RECORDS:
            issues.append(
                DetectionIssue("service_oversized", "stored", "Stored evidence exceeded the limit")
            )
            evidence = evidence[:MAX_RECORDS]
        for item in evidence:
            try:
                domain = normalize_domain(item.domain)
                if domain not in domains:
                    raise ADDetectionError("stored evidence domain was not approved")
                host = _hostname(item.host, domain)
                address = str(ipaddress.IPv4Address(item.address))
                if item.port not in AD_PORTS and item.service.casefold() not in AD_SERVICE_NAMES:
                    continue
            except (ADDetectionError, ValueError, AttributeError):
                issues.append(
                    DetectionIssue(
                        "malformed_service",
                        "stored",
                        "Malformed stored service evidence was ignored",
                    )
                )
                continue
            state = states[(domain, host)]
            state.addresses.add(address)
            state.ports.add(item.port)
            state.sources.add(item.source)

    async def _resolve_and_probe(
        self,
        states: dict[tuple[str, str], _CandidateState],
        issues: list[DetectionIssue],
    ) -> None:
        semaphore = asyncio.Semaphore(self.concurrency)

        async def one(domain: str, host: str, state: _CandidateState) -> None:
            if not state.addresses:
                try:
                    addresses = await self.resolver.resolve_ipv4(host)
                except ADDetectionUnreachable:
                    issues.append(
                        DetectionIssue("dns_unreachable", host, "Address lookup was unreachable")
                    )
                    return
                except ADDetectionError:
                    issues.append(DetectionIssue("dns_error", host, "Address lookup failed safely"))
                    return
                for address in addresses[:MAX_RECORDS]:
                    try:
                        state.addresses.add(str(ipaddress.IPv4Address(address)))
                    except ValueError:
                        issues.append(
                            DetectionIssue(
                                "malformed_address", host, "Malformed IPv4 address was ignored"
                            )
                        )
            approved: list[str] = []
            for address in sorted(state.addresses):
                try:
                    approved.append(approve_target(address, self.approved_ranges))
                except (TargetApprovalError, ValueError):
                    issues.append(
                        DetectionIssue(
                            "target_refused", host, "RootDSE target was outside approved ranges"
                        )
                    )
            state.addresses.intersection_update(approved)
            probe_port = 636 if 636 in state.ports else 389
            for address in approved:
                try:
                    async with semaphore:
                        raw = await self.rootdse_probe.query(address, probe_port)
                    rootdse = _normalize_rootdse(raw)
                except ADDetectionUnreachable:
                    issues.append(
                        DetectionIssue("rootdse_unreachable", address, "RootDSE was unreachable")
                    )
                    continue
                except ADDetectionError:
                    issues.append(
                        DetectionIssue(
                            "rootdse_malformed", address, "RootDSE response was rejected"
                        )
                    )
                    continue
                if _rootdse_confirms_ad(rootdse, domain):
                    state.rootdse = rootdse
                    state.rootdse_confirmed = True
                    state.sources.add("anonymous_rootdse")
                    break
                issues.append(
                    DetectionIssue(
                        "rootdse_not_ad", address, "RootDSE did not confirm the approved AD domain"
                    )
                )

        await asyncio.gather(
            *(one(domain, host, state) for (domain, host), state in sorted(states.items()))
        )


def repository_service_evidence(
    repository: Repository, deployment_id: int, domains: Sequence[str]
) -> tuple[ServiceEvidence, ...]:
    """Read bounded existing nmap/service facts without initiating any probe."""
    approved = tuple(normalize_domain(value) for value in domains)
    rows = repository.connection.execute(
        "SELECT s.port, COALESCE(s.service_name, ''), s.source, "
        "(SELECT da.alias_value FROM device_aliases da WHERE da.device_id = d.id "
        " AND da.alias_kind = 'hostname' ORDER BY da.observed_at DESC LIMIT 1) AS hostname, "
        "(SELECT aa.address FROM address_assignments aa WHERE aa.device_id = d.id "
        " AND aa.address_kind = 'ipv4' ORDER BY aa.observed_at DESC LIMIT 1) AS address "
        "FROM services s JOIN devices d ON d.id = s.device_id "
        "WHERE d.deployment_id = ? AND s.state IN ('open', 'open|filtered') "
        "ORDER BY d.id, s.port LIMIT ?",
        (deployment_id, MAX_RECORDS + 1),
    ).fetchall()
    result: list[ServiceEvidence] = []
    for row in rows[:MAX_RECORDS]:
        host = row[3]
        address = row[4]
        if not isinstance(host, str) or not isinstance(address, str):
            continue
        domain = next((item for item in approved if host.casefold().endswith(f".{item}")), None)
        if domain is None:
            continue
        result.append(ServiceEvidence(domain, host, address, int(row[0]), str(row[1]), str(row[2])))
    return tuple(result)


def persist_detection(
    repository: Repository,
    deployment_id: int,
    result: ADDetectionResult,
    *,
    observed_at: datetime | None = None,
) -> int:
    """Persist candidates and limitations as provenance-aware non-secret observations."""
    timestamp = (observed_at or datetime.now(UTC)).astimezone(UTC).isoformat()
    count = 0
    for candidate in result.candidates:
        repository.record_observation(
            deployment_id,
            subject_type="ad_domain_controller_candidate",
            subject_id=None,
            fact_type="ad.detection",
            fact_value={
                "domain": candidate.domain,
                "hostname": candidate.hostname,
                "addresses": candidate.addresses,
                "ports": candidate.ports,
                "sites": candidate.sites,
                "sources": candidate.sources,
                "rootdse": candidate.rootdse,
            },
            confidence=candidate.confidence,
            inferred=False,
            source="ad_detection",
            observed_at=timestamp,
        )
        count += 1
    for issue in result.issues:
        repository.record_observation(
            deployment_id,
            subject_type="ad_detection_limitation",
            subject_id=None,
            fact_type=issue.category,
            fact_value={"subject": issue.subject, "detail": issue.detail},
            confidence=1.0,
            inferred=False,
            source="ad_detection",
            observed_at=timestamp,
        )
    return count
