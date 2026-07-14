"""Credential-gated, documentation-only Active Directory collection."""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import stat
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

import ldap3  # type: ignore[import-untyped]

from field_discovery.ad_detection import ROOTDSE_ATTRIBUTES, normalize_domain
from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CollectorError,
    CollectorIssue,
    CollectorResult,
    CredentialReference,
    RetryableCollectorError,
)
from field_discovery.repository import Repository

MAX_SECRET_BYTES = 65_536
MAX_ATTRIBUTE_TEXT = 4096
MAX_ATTRIBUTE_VALUES = 100_000
MAX_REFERRALS = 32
LDAP_PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"
_FORBIDDEN_ATTRIBUTE = re.compile(
    r"(?:passw|passwd|unicodepwd|supplementalcredentials|ntpassword|lmhash|nthash|"
    r"managedpassword|ms-mcs-admpwd|laps|privatekey|secret|token|ticket|credential|"
    r"allowedtoactonbehalfofotheridentity|securitydescriptor|attack)",
    re.I,
)
_MEMBER_RANGE = re.compile(r"^member;range=(\d+)-(\d+|\*)$", re.I)


class ADCollectionError(CollectorError):
    """A safe, secret-free directory collection failure."""


class ADAuthorizationError(ADCollectionError):
    """The account cannot read one documentation domain."""


@dataclass(frozen=True)
class ADCredentials:
    """Ephemeral authentication material resolved from an opaque reference."""

    mode: str
    identity: str
    password: str | None = None

    @classmethod
    def from_secret(cls, raw: str, transport: str) -> ADCredentials:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ADCollectionError("referenced AD credential profile is not valid JSON") from exc
        if not isinstance(value, dict):
            raise ADCollectionError("referenced AD credential profile must be a mapping")
        if transport == "kerberos":
            if set(value) != {"principal", "use_system_ccache"}:
                raise ADCollectionError(
                    "Kerberos AD profile must contain principal and use_system_ccache"
                )
            principal = value.get("principal")
            if (
                not isinstance(principal, str)
                or not principal
                or value.get("use_system_ccache") is not True
            ):
                raise ADCollectionError("Kerberos AD profile fields are invalid")
            return cls("kerberos", principal)
        if transport not in {"ldaps", "ldap"}:
            raise ADCollectionError("AD transport is unsupported")
        if set(value) != {"username", "password"}:
            raise ADCollectionError("LDAP AD profile must contain username and password")
        username, password = value.get("username"), value.get("password")
        if (
            not isinstance(username, str)
            or not username
            or not isinstance(password, str)
            or not password
        ):
            raise ADCollectionError("LDAP AD profile fields are invalid")
        return cls("password", username, password)


def resolve_ad_credentials(
    reference: CredentialReference,
    providers: Mapping[str, Mapping[str, object]],
    transport: str,
) -> ADCredentials:
    """Resolve one bounded profile without argv, shell, or persistent storage exposure."""
    provider = providers.get(reference.provider)
    if provider is None:
        raise ADCollectionError("AD credential provider is unavailable")
    provider_type = provider.get("type")
    secret: str | None = None
    if provider_type == "env_file":
        path = Path(str(provider.get("path", "")))
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid not in {0, os.geteuid()}
            ):
                raise ADCollectionError("AD credential file ownership or mode is unsafe")
            raw = path.read_bytes()
        except OSError as exc:
            raise ADCollectionError("AD credential file is unavailable") from exc
        if len(raw) > MAX_SECRET_BYTES:
            raise ADCollectionError("AD credential file exceeds the size limit")
        try:
            lines = raw.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError as exc:
            raise ADCollectionError("AD credential file is not valid UTF-8") from exc
        for line in lines:
            key, separator, value = line.partition("=")
            if separator and key == reference.key:
                secret = value
                break
    elif provider_type == "command":
        timeout = provider.get("timeout_seconds", 5)
        if isinstance(timeout, bool) or not isinstance(timeout, int):
            raise ADCollectionError("AD credential command timeout is invalid")
        try:
            completed = subprocess.run(
                [str(provider.get("executable", ""))],
                input=f"{reference.key}\n",
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={"PATH": "/usr/bin:/bin"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ADCollectionError("AD credential command failed") from exc
        if completed.returncode != 0 or len(completed.stdout.encode()) > MAX_SECRET_BYTES:
            raise ADCollectionError("AD credential command failed")
        secret = completed.stdout.rstrip("\r\n")
    else:
        raise ADCollectionError("AD credential provider type is unsupported")
    if not secret:
        raise ADCollectionError("referenced AD credential is unavailable")
    return ADCredentials.from_secret(secret, transport)


@dataclass(frozen=True)
class LDAPPage:
    """One bounded LDAP page with referrals disclosed but never followed."""

    entries: tuple[Mapping[str, object], ...]
    cookie: bytes
    referrals: tuple[str, ...] = ()


class LDAPSession(Protocol):
    """Small async LDAP boundary used by the collector and fixture sessions."""

    async def search(
        self,
        base: str,
        ldap_filter: str,
        scope: str,
        attributes: Sequence[str],
        *,
        page_size: int,
        cookie: bytes,
    ) -> LDAPPage:
        """Return one page for a fixed documentation query."""

    async def close(self) -> None:
        """Close the directory session."""


class LDAPSessionFactory(Protocol):
    """Create one approved credential-gated directory session."""

    async def connect(
        self,
        target: str,
        server_name: str,
        transport: str,
        credential: ADCredentials,
        *,
        timeout: float,
    ) -> LDAPSession:
        """Connect to one already approved target."""


class _Ldap3Session:
    def __init__(self, connection: Any) -> None:
        self.connection = connection

    async def search(
        self,
        base: str,
        ldap_filter: str,
        scope: str,
        attributes: Sequence[str],
        *,
        page_size: int,
        cookie: bytes,
    ) -> LDAPPage:
        return await asyncio.to_thread(
            self._search_sync,
            base,
            ldap_filter,
            scope,
            attributes,
            page_size,
            cookie,
        )

    def _search_sync(
        self,
        base: str,
        ldap_filter: str,
        scope: str,
        attributes: Sequence[str],
        page_size: int,
        cookie: bytes,
    ) -> LDAPPage:
        scope_value = {"base": ldap3.BASE, "one": ldap3.LEVEL, "subtree": ldap3.SUBTREE}[scope]
        try:
            ok = self.connection.search(
                base,
                ldap_filter,
                search_scope=scope_value,
                attributes=list(attributes),
                paged_size=page_size,
                paged_cookie=cookie or None,
            )
        except Exception as exc:
            _map_ldap_exception(exc, operation="query")
        result = cast(Mapping[str, object], self.connection.result)
        code = result.get("result")
        if not ok or code not in {0, None}:
            if code in {49}:
                raise CollectorAuthenticationError("referenced AD credential was rejected")
            if code in {50, 53}:
                raise ADAuthorizationError("AD query was not permitted")
            raise ADCollectionError("AD query failed")
        entries: list[Mapping[str, object]] = []
        referrals: list[str] = []
        for response in self.connection.response:
            response_type = response.get("type")
            if response_type == "searchResEntry":
                attributes_value = response.get("attributes")
                if isinstance(attributes_value, Mapping):
                    entry = dict(attributes_value)
                    entry.setdefault("distinguishedName", str(response.get("dn", "")))
                    entries.append(entry)
            elif response_type == "searchResRef":
                uri = response.get("uri", ())
                values = uri if isinstance(uri, list | tuple) else (uri,)
                referrals.extend(str(item)[:1024] for item in values[:MAX_REFERRALS])
        controls = result.get("controls")
        next_cookie = b""
        if isinstance(controls, Mapping):
            paging = controls.get(LDAP_PAGED_RESULTS_OID)
            if isinstance(paging, Mapping):
                value = paging.get("value")
                if isinstance(value, Mapping) and isinstance(value.get("cookie"), bytes):
                    next_cookie = cast(bytes, value["cookie"])
        return LDAPPage(tuple(entries), next_cookie, tuple(referrals[:MAX_REFERRALS]))

    async def close(self) -> None:
        await asyncio.to_thread(self.connection.unbind)


def _map_ldap_exception(exc: Exception, *, operation: str) -> None:
    name = type(exc).__name__.casefold()
    text = str(exc).casefold()
    if "invalidcredential" in name or "credential" in text or "ticket expired" in text:
        raise CollectorAuthenticationError("referenced AD credential was rejected") from exc
    if "insufficient" in name or "authorization" in name:
        raise ADAuthorizationError(f"AD {operation} was not permitted") from exc
    if "timeout" in name or "socket" in name or "communication" in name:
        raise RetryableCollectorError(f"AD {operation} timed out") from exc
    raise ADCollectionError(f"AD {operation} failed") from exc


class Ldap3SessionFactory:
    """Strict-TLS ldap3 adapter supporting system-ccache Kerberos and LDAP bind."""

    async def connect(
        self,
        target: str,
        server_name: str,
        transport: str,
        credential: ADCredentials,
        *,
        timeout: float,
    ) -> LDAPSession:
        return await asyncio.to_thread(
            self._connect_sync, target, server_name, transport, credential, timeout
        )

    @staticmethod
    def _connect_sync(
        target: str,
        server_name: str,
        transport: str,
        credential: ADCredentials,
        timeout: float,
    ) -> LDAPSession:
        use_ssl = transport == "ldaps"
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, valid_names=[server_name]) if use_ssl else None
        server = ldap3.Server(
            target,
            port=636 if use_ssl else 389,
            use_ssl=use_ssl,
            tls=tls,
            connect_timeout=timeout,
            get_info=ldap3.NONE,
        )
        parameters: dict[str, object] = {
            "auto_bind": True,
            "raise_exceptions": True,
            "receive_timeout": timeout,
            "auto_referrals": False,
        }
        if transport == "kerberos":
            if credential.mode != "kerberos":
                raise ADCollectionError("Kerberos transport requires a Kerberos credential profile")
            parameters.update(
                {
                    "user": credential.identity,
                    "authentication": ldap3.SASL,
                    "sasl_mechanism": ldap3.KERBEROS,
                    "sasl_credentials": (None, server_name),
                }
            )
        else:
            if credential.mode != "password" or credential.password is None:
                raise ADCollectionError("LDAP transport requires a password credential profile")
            parameters.update(
                {
                    "user": credential.identity,
                    "password": credential.password,
                    "authentication": ldap3.SIMPLE,
                }
            )
        try:
            connection = ldap3.Connection(server, **parameters)
        except Exception as exc:
            _map_ldap_exception(exc, operation="connection")
        return _Ldap3Session(connection)


@dataclass(frozen=True)
class QuerySpec:
    kind: str
    base: str
    ldap_filter: str
    scope: str
    attributes: tuple[str, ...]
    key_attribute: str


@dataclass(frozen=True)
class ADRecord:
    kind: str
    key: str
    attributes: Mapping[str, object]


ROOT_QUERY = QuerySpec(
    "root",
    "",
    "(objectClass=*)",
    "base",
    ROOTDSE_ATTRIBUTES,
    "defaultNamingContext",
)
DOMAIN_ATTRIBUTES = (
    "distinguishedName",
    "objectGUID",
    "name",
    "objectSid",
    "msDS-Behavior-Version",
)
COMPUTER_ATTRIBUTES = (
    "distinguishedName",
    "objectGUID",
    "sAMAccountName",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "userAccountControl",
    "servicePrincipalName",
)
SITE_ATTRIBUTES = ("distinguishedName", "objectGUID", "name", "description")
SUBNET_ATTRIBUTES = ("distinguishedName", "objectGUID", "name", "siteObject", "location")
OU_ATTRIBUTES = ("distinguishedName", "objectGUID", "name", "description")
TRUST_ATTRIBUTES = (
    "distinguishedName",
    "objectGUID",
    "name",
    "trustDirection",
    "trustType",
    "trustAttributes",
)
GROUP_ATTRIBUTES = (
    "distinguishedName",
    "objectGUID",
    "sAMAccountName",
    "displayName",
    "description",
    "groupType",
    "member",
)


def _escape_filter(value: str) -> str:
    return "".join(
        {"*": r"\2a", "(": r"\28", ")": r"\29", "\\": r"\5c", "\0": r"\00"}.get(
            character, character
        )
        for character in value
    )


def _query_specs(
    base_dn: str, configuration_dn: str, documentation_groups: Sequence[str]
) -> tuple[QuerySpec, ...]:
    specs = [
        QuerySpec(
            "domain",
            base_dn,
            "(objectClass=domainDNS)",
            "base",
            DOMAIN_ATTRIBUTES,
            "distinguishedName",
        ),
        QuerySpec(
            "domain_controller",
            base_dn,
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            "subtree",
            COMPUTER_ATTRIBUTES,
            "objectGUID",
        ),
        QuerySpec(
            "computer",
            base_dn,
            "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
            "subtree",
            COMPUTER_ATTRIBUTES,
            "objectGUID",
        ),
        QuerySpec(
            "organizational_unit",
            base_dn,
            "(objectClass=organizationalUnit)",
            "subtree",
            OU_ATTRIBUTES,
            "objectGUID",
        ),
        QuerySpec(
            "trust",
            base_dn,
            "(objectClass=trustedDomain)",
            "subtree",
            TRUST_ATTRIBUTES,
            "objectGUID",
        ),
        QuerySpec(
            "site",
            f"CN=Sites,{configuration_dn}",
            "(objectClass=site)",
            "subtree",
            SITE_ATTRIBUTES,
            "objectGUID",
        ),
        QuerySpec(
            "subnet",
            f"CN=Subnets,CN=Sites,{configuration_dn}",
            "(objectClass=subnet)",
            "subtree",
            SUBNET_ATTRIBUTES,
            "objectGUID",
        ),
    ]
    if documentation_groups:
        group_filter = (
            "(|"
            + "".join(f"(sAMAccountName={_escape_filter(name)})" for name in documentation_groups)
            + ")"
        )
        specs.append(
            QuerySpec(
                "group",
                base_dn,
                f"(&(objectCategory=group){group_filter})",
                "subtree",
                GROUP_ATTRIBUTES,
                "objectGUID",
            )
        )
    return tuple(specs)


def _safe_value(value: object) -> object:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, str):
        return value[:MAX_ATTRIBUTE_TEXT]
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, list | tuple):
        return [_safe_value(item) for item in value[:MAX_ATTRIBUTE_VALUES]]
    return str(value)[:MAX_ATTRIBUTE_TEXT]


def _sanitize_entry(
    entry: Mapping[str, object], allowed: Sequence[str]
) -> tuple[dict[str, object], int]:
    allowed_folded = {name.split(";", 1)[0].casefold() for name in allowed}
    result: dict[str, object] = {}
    filtered = 0
    for name, value in entry.items():
        base_name = name.split(";", 1)[0]
        if _FORBIDDEN_ATTRIBUTE.search(base_name) or base_name.casefold() not in allowed_folded:
            filtered += 1
            continue
        result[name] = _safe_value(value)
    return result, filtered


def _first(attributes: Mapping[str, object], name: str) -> str | None:
    value = attributes.get(name)
    if isinstance(value, list) and value:
        value = value[0]
    return str(value) if value is not None and value != "" else None


class ActiveDirectoryCollector:
    """Run fixed documentation queries with bounded paging and partial isolation."""

    name = "ad"

    def __init__(
        self,
        repository: Repository,
        deployment_id: int,
        session_factory: LDAPSessionFactory,
        credential_resolver: Any,
        *,
        domain: str,
        base_dn: str,
        transport: str,
        allow_plaintext_ldap: bool,
        server_name: str,
        page_size: int,
        max_entries: int,
        documentation_groups: Sequence[str],
        timeout: float,
        clock: Any = lambda: datetime.now(UTC),
    ) -> None:
        if transport == "ldap" and not allow_plaintext_ldap:
            raise ADCollectionError("plaintext LDAP requires explicit opt-in")
        if transport not in {"kerberos", "ldaps", "ldap"}:
            raise ADCollectionError("AD transport is unsupported")
        if not 1 <= page_size <= 1000 or not 1 <= max_entries <= 100_000:
            raise ADCollectionError("AD paging limits are invalid")
        if len(documentation_groups) > 128 or any(
            not isinstance(name, str) or not name or len(name) > 256
            for name in documentation_groups
        ):
            raise ADCollectionError("AD documentation group list is invalid")
        self.repository = repository
        self.deployment_id = deployment_id
        self.session_factory = session_factory
        self.credential_resolver = credential_resolver
        self.domain = normalize_domain(domain)
        self.base_dn = base_dn
        self.transport = transport
        self.server_name = server_name
        self.page_size = page_size
        self.max_entries = max_entries
        self.documentation_groups = tuple(sorted(set(documentation_groups)))
        self.timeout = timeout
        self.clock = clock

    async def collect(self, context: CollectorContext) -> CollectorResult:
        if context.credential_ref is None:
            raise ADCollectionError("AD collection requires an explicit credential reference")
        credential = self.credential_resolver(context.credential_ref, self.transport)
        session = await self.session_factory.connect(
            context.target,
            self.server_name,
            self.transport,
            credential,
            timeout=self.timeout,
        )
        issues: list[CollectorIssue] = []
        records: list[ADRecord] = []
        try:
            root_records, root_issues = await self._run_query(session, ROOT_QUERY, context)
            issues.extend(root_issues)
            if not root_records:
                raise ADCollectionError("AD RootDSE did not return directory metadata")
            root = root_records[0].attributes
            actual_base = _first(root, "defaultNamingContext")
            configuration_dn = _first(root, "configurationNamingContext")
            if actual_base is None or actual_base.casefold() != self.base_dn.casefold():
                raise ADCollectionError(
                    "AD RootDSE naming context does not match configured base DN"
                )
            if configuration_dn is None:
                raise ADCollectionError("AD RootDSE lacks a configuration naming context")
            records.extend(root_records)
            for spec in _query_specs(self.base_dn, configuration_dn, self.documentation_groups):
                if context.cancellation.is_set():
                    raise asyncio.CancelledError
                try:
                    query_records, query_issues = await self._run_query(session, spec, context)
                    if spec.kind == "group":
                        range_issues = await self._expand_group_ranges(
                            session, query_records, context
                        )
                        query_issues.extend(range_issues)
                    records.extend(query_records)
                    issues.extend(query_issues)
                except ADAuthorizationError:
                    issues.append(
                        CollectorIssue(
                            "ad_insufficient_access", f"read access denied for {spec.kind}"
                        )
                    )
                except ADCollectionError:
                    issues.append(
                        CollectorIssue("ad_partial_query", f"query failed safely for {spec.kind}")
                    )
            issues.extend(self._persist(records))
        finally:
            await session.close()
        return CollectorResult(len(records), tuple(issues))

    async def _run_query(
        self, session: LDAPSession, spec: QuerySpec, context: CollectorContext
    ) -> tuple[list[ADRecord], list[CollectorIssue]]:
        records: list[ADRecord] = []
        positions: dict[str, int] = {}
        issues: list[CollectorIssue] = []
        cookie = b""
        seen_cookies: set[bytes] = set()
        filtered = 0
        while True:
            if context.cancellation.is_set():
                raise asyncio.CancelledError
            page = await session.search(
                spec.base,
                spec.ldap_filter,
                spec.scope,
                spec.attributes,
                page_size=self.page_size,
                cookie=cookie,
            )
            if page.referrals:
                issues.append(
                    CollectorIssue(
                        "ad_referral_not_followed",
                        f"{len(page.referrals)} referrals not followed for {spec.kind}",
                    )
                )
            for entry in page.entries:
                attributes, removed = _sanitize_entry(entry, spec.attributes)
                filtered += removed
                key = _first(attributes, spec.key_attribute) or _first(
                    attributes, "distinguishedName"
                )
                if key is None:
                    issues.append(
                        CollectorIssue("ad_malformed_entry", f"entry omitted for {spec.kind}")
                    )
                    continue
                if key in positions:
                    position = positions[key]
                    combined = dict(records[position].attributes)
                    combined.update(attributes)
                    records[position] = ADRecord(spec.kind, key, combined)
                else:
                    positions[key] = len(records)
                    records.append(ADRecord(spec.kind, key, attributes))
                if len(records) >= self.max_entries:
                    issues.append(
                        CollectorIssue("ad_entry_limit", f"entry limit reached for {spec.kind}")
                    )
                    cookie = b""
                    break
            if not page.cookie or len(records) >= self.max_entries:
                break
            if page.cookie in seen_cookies:
                raise ADCollectionError("AD paging cookie repeated")
            seen_cookies.add(page.cookie)
            cookie = page.cookie
        if filtered:
            issues.append(
                CollectorIssue(
                    "ad_attributes_filtered",
                    f"{filtered} unapproved attributes filtered for {spec.kind}",
                )
            )
        return records, issues

    async def _expand_group_ranges(
        self,
        session: LDAPSession,
        groups: Sequence[ADRecord],
        context: CollectorContext,
    ) -> list[CollectorIssue]:
        issues: list[CollectorIssue] = []
        for group in groups:
            attributes = cast(dict[str, object], group.attributes)
            seen_starts: set[int] = set()
            while True:
                pending: tuple[int, int] | None = None
                has_terminal_range = False
                total_members = 0
                for name, value in attributes.items():
                    match = _MEMBER_RANGE.fullmatch(name)
                    if not match:
                        continue
                    values = value if isinstance(value, list) else [value]
                    total_members += len(values)
                    if match.group(2) == "*":
                        has_terminal_range = True
                    else:
                        pending = (int(match.group(1)), int(match.group(2)))
                if pending is None or has_terminal_range:
                    break
                next_start = pending[1] + 1
                if next_start in seen_starts or total_members >= MAX_ATTRIBUTE_VALUES:
                    issues.append(
                        CollectorIssue(
                            "ad_group_range_limit",
                            f"membership range stopped safely for {group.key}",
                        )
                    )
                    break
                seen_starts.add(next_start)
                range_attribute = f"member;range={next_start}-*"
                spec = QuerySpec(
                    "group_membership_range",
                    _first(attributes, "distinguishedName") or group.key,
                    "(objectClass=*)",
                    "base",
                    ("distinguishedName", "objectGUID", range_attribute),
                    "objectGUID",
                )
                range_records, range_issues = await self._run_query(session, spec, context)
                issues.extend(range_issues)
                if not range_records:
                    issues.append(
                        CollectorIssue(
                            "ad_group_range_partial",
                            f"membership range unavailable for {group.key}",
                        )
                    )
                    break
                new_values = {
                    name: value
                    for name, value in range_records[0].attributes.items()
                    if _MEMBER_RANGE.fullmatch(name)
                }
                if not new_values:
                    issues.append(
                        CollectorIssue(
                            "ad_group_range_partial",
                            f"membership range malformed for {group.key}",
                        )
                    )
                    break
                attributes.update(new_values)
        return issues

    def _persist(self, records: Sequence[ADRecord]) -> list[CollectorIssue]:
        observed = self.clock().astimezone(UTC).isoformat()
        root = next(record for record in records if record.kind == "root")
        forest_dn = _first(root.attributes, "rootDomainNamingContext")
        forest_name = _dn_to_domain(forest_dn) if forest_dn else None
        with self.repository.transaction():
            cursor = self.repository.connection.execute(
                "INSERT INTO ad_domains"
                "(deployment_id,domain_key,dns_name,forest_name,functional_level,"
                "source,observed_at) "
                "VALUES (?, ?, ?, ?, NULL, 'ad_ldap', ?)",
                (self.deployment_id, self.domain, self.domain, forest_name, observed),
            )
            if cursor.lastrowid is None:  # pragma: no cover - SQLite INSERT contract
                raise ADCollectionError("AD domain persistence did not return an identifier")
            domain_id = cursor.lastrowid
            for record in records:
                if record.kind in {"root", "domain", "trust"}:
                    self.repository.connection.execute(
                        "INSERT INTO observations"
                        "(deployment_id,subject_type,subject_id,fact_type,fact_value_json,"
                        "confidence,inferred,source,observed_at) "
                        "VALUES (?, 'ad_directory', NULL, ?, ?, 1.0, 0, 'ad_ldap', ?)",
                        (
                            self.deployment_id,
                            f"ad.{record.kind}",
                            json.dumps(record.attributes, sort_keys=True, separators=(",", ":")),
                            observed,
                        ),
                    )
                    continue
                kind = record.kind
                attributes = dict(record.attributes)
                display = (
                    _first(attributes, "displayName")
                    or _first(attributes, "name")
                    or _first(attributes, "sAMAccountName")
                )
                dns_name = _first(attributes, "dNSHostName")
                operating_system = _first(attributes, "operatingSystem")
                self.repository.connection.execute(
                    "INSERT INTO ad_entities"
                    "(ad_domain_id,entity_key,entity_kind,display_name,dns_name,operating_system,"
                    "attributes_json,source,observed_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'ad_ldap', ?)",
                    (
                        domain_id,
                        record.key,
                        kind,
                        display,
                        dns_name,
                        operating_system,
                        json.dumps(attributes, sort_keys=True, separators=(",", ":")),
                        observed,
                    ),
                )
                if kind == "domain_controller":
                    for role in _server_roles(attributes):
                        self.repository.connection.execute(
                            "INSERT INTO ad_entities"
                            "(ad_domain_id,entity_key,entity_kind,display_name,"
                            "attributes_json,source,observed_at) "
                            "VALUES (?, ?, 'server_role', ?, '{}', 'ad_ldap', ?)",
                            (domain_id, f"{record.key}:{role}", role, observed),
                        )
        return []


def _dn_to_domain(value: str) -> str | None:
    labels = [
        component.partition("=")[2]
        for component in value.split(",")
        if component.strip().casefold().startswith("dc=")
    ]
    return ".".join(labels).casefold() if labels else None


def _server_roles(attributes: Mapping[str, object]) -> tuple[str, ...]:
    value = attributes.get("servicePrincipalName", ())
    values = value if isinstance(value, list) else [value]
    roles: set[str] = {"domain_controller"}
    for item in values:
        if not isinstance(item, str):
            continue
        service = item.partition("/")[0].casefold()
        role = {
            "dns": "dns_server",
            "gc": "global_catalog",
            "ldap": "ldap_server",
            "kadmin": "kerberos_admin",
        }.get(service)
        if role:
            roles.add(role)
    return tuple(sorted(roles))
