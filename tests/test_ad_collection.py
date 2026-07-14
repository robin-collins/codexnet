"""Mock-only credential-gated AD collection and adapter tests."""

from __future__ import annotations

import asyncio
import json
import ssl
import subprocess
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar, cast

import ldap3  # type: ignore[import-untyped]
import pytest

import field_discovery.ad_collection as ad_module
from field_discovery.ad_collection import (
    MAX_ATTRIBUTE_VALUES,
    MAX_SECRET_BYTES,
    ActiveDirectoryCollector,
    ADAuthorizationError,
    ADCollectionError,
    ADCredentials,
    Ldap3SessionFactory,
    LDAPPage,
    QuerySpec,
    _dn_to_domain,
    _escape_filter,
    _first,
    _Ldap3Session,
    _query_specs,
    _safe_value,
    _sanitize_entry,
    _server_roles,
    resolve_ad_credentials,
)
from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CredentialReference,
    RetryableCollectorError,
)
from field_discovery.repository import Repository

ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests/fixtures/ad/directory.json"
NOW = datetime(2026, 7, 15, 3, 4, 5, tzinfo=UTC)
REFERENCE = CredentialReference("fixture", "AD_PROFILE")


def fixture() -> dict[str, dict[str, object]]:
    return cast(dict[str, dict[str, object]], json.loads(FIXTURE.read_text()))


def repository(tmp_path: Path) -> tuple[Repository, int]:
    root = tmp_path / "data"
    root.mkdir(mode=0o700)
    repo = Repository.open(root / "discovery.db", data_root=root)
    deployment = repo.upsert_deployment("fixture", "Fixture", NOW.isoformat())
    return repo, deployment


class FixtureSession:
    def __init__(
        self,
        pages: Mapping[str, Sequence[LDAPPage | BaseException]],
    ) -> None:
        self.pages = {key: list(value) for key, value in pages.items()}
        self.calls: list[tuple[str, str, str, tuple[str, ...], int, bytes]] = []
        self.closed = False

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
        self.calls.append((base, ldap_filter, scope, tuple(attributes), page_size, cookie))
        if base == "":
            key = "root"
        elif "domainDNS" in ldap_filter:
            key = "domain"
        elif "8192" in ldap_filter and "!(" not in ldap_filter:
            key = "domain_controller"
        elif "objectCategory=computer" in ldap_filter:
            key = "computer"
        elif "organizationalUnit" in ldap_filter:
            key = "organizational_unit"
        elif "trustedDomain" in ldap_filter:
            key = "trust"
        elif "objectClass=site" in ldap_filter:
            key = "site"
        elif "objectClass=subnet" in ldap_filter:
            key = "subnet"
        else:
            key = "group"
        actions = self.pages.get(key, [LDAPPage((), b"")])
        action = actions.pop(0)
        if isinstance(action, BaseException):
            raise action
        return action

    async def close(self) -> None:
        self.closed = True


class FixtureFactory:
    def __init__(self, session: FixtureSession | BaseException) -> None:
        self.session = session
        self.calls: list[tuple[str, str, str, ADCredentials, float]] = []

    async def connect(
        self,
        target: str,
        server_name: str,
        transport: str,
        credential: ADCredentials,
        *,
        timeout: float,
    ) -> FixtureSession:
        self.calls.append((target, server_name, transport, credential, timeout))
        if isinstance(self.session, BaseException):
            raise self.session
        return self.session


def pages_from_fixture() -> dict[str, list[LDAPPage]]:
    value = fixture()
    return {name: [LDAPPage((attributes,), b"")] for name, attributes in value.items()}


def collector(
    repo: Repository,
    deployment: int,
    factory: FixtureFactory,
    **overrides: object,
) -> ActiveDirectoryCollector:
    values: dict[str, object] = {
        "repository": repo,
        "deployment_id": deployment,
        "session_factory": factory,
        "credential_resolver": lambda _reference, transport: ADCredentials(
            "kerberos" if transport == "kerberos" else "password",
            "fixture-principal",
            None if transport == "kerberos" else "synthetic-secret",
        ),
        "domain": "example.invalid",
        "base_dn": "DC=example,DC=invalid",
        "transport": "ldaps",
        "allow_plaintext_ldap": False,
        "server_name": "dc1.example.invalid",
        "page_size": 500,
        "max_entries": 10_000,
        "documentation_groups": ("Documentation",),
        "timeout": 5,
        "clock": lambda: NOW,
    }
    values.update(overrides)
    return ActiveDirectoryCollector(**values)  # type: ignore[arg-type]


def context(*, reference: CredentialReference | None = REFERENCE) -> CollectorContext:
    return CollectorContext("192.168.50.10", reference, asyncio.Event())


def test_complete_directory_fixture_persists_all_documentation_domains(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    session = FixtureSession(pages_from_fixture())
    factory = FixtureFactory(session)
    result = asyncio.run(collector(repo, deployment, factory).collect(context()))
    assert result.item_count == 9
    assert result.issues == ()
    assert session.closed
    assert factory.calls[0][0:3] == (
        "192.168.50.10",
        "dc1.example.invalid",
        "ldaps",
    )
    assert repo.connection.execute("SELECT count(*) FROM ad_domains").fetchone()[0] == 1
    kinds = {
        row[0] for row in repo.connection.execute("SELECT entity_kind FROM ad_entities ORDER BY id")
    }
    assert kinds == {
        "domain_controller",
        "computer",
        "organizational_unit",
        "site",
        "subnet",
        "group",
        "server_role",
    }
    roles = {
        row[0]
        for row in repo.connection.execute(
            "SELECT display_name FROM ad_entities WHERE entity_kind='server_role'"
        )
    }
    assert roles == {"dns_server", "domain_controller", "global_catalog", "ldap_server"}
    assert repo.connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 3
    payload = "\n".join(
        str(row[0])
        for row in repo.connection.execute(
            "SELECT attributes_json FROM ad_entities "
            "UNION ALL SELECT fact_value_json FROM observations"
        )
    )
    assert "synthetic-secret" not in payload
    repo.close()


def test_paging_referrals_large_group_and_attribute_filtering(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    pages = pages_from_fixture()
    group = fixture()["group"]
    first = dict(group)
    first["member;range=0-1499"] = [
        f"CN=Member{index},DC=example,DC=invalid" for index in range(1500)
    ]
    first["unicodePwd"] = "forbidden"
    first["madeUpAttribute"] = "ignored"
    second = dict(group)
    second["member;range=1500-*"] = ["CN=Member1500,DC=example,DC=invalid"]
    pages["group"] = [
        LDAPPage((first,), b"next", ("ldap://other.invalid",)),
        LDAPPage((second,), b""),
    ]
    session = FixtureSession(pages)
    result = asyncio.run(collector(repo, deployment, FixtureFactory(session)).collect(context()))
    categories = [issue.category for issue in result.issues]
    assert categories == [
        "ad_referral_not_followed",
        "ad_attributes_filtered",
    ]
    group_calls = [call for call in session.calls if "objectCategory=group" in call[1]]
    assert [call[-1] for call in group_calls] == [b"", b"next"]
    stored = repo.connection.execute(
        "SELECT attributes_json FROM ad_entities WHERE entity_kind='group' ORDER BY id"
    ).fetchall()
    assert len(stored) == 1
    assert "member;range=0-1499" in stored[0][0]
    assert "member;range=1500-*" in stored[0][0]
    assert all("unicodePwd" not in row[0] and "madeUpAttribute" not in row[0] for row in stored)
    repo.close()


def test_large_group_member_ranges_are_retrieved_explicitly(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    pages = pages_from_fixture()
    first = dict(fixture()["group"])
    first.pop("member;range=0-*")
    first["member;range=0-1499"] = ["CN=Member0,DC=example,DC=invalid"]
    continuation = {
        "distinguishedName": first["distinguishedName"],
        "objectGUID": first["objectGUID"],
        "member;range=1500-*": ["CN=Member1500,DC=example,DC=invalid"],
    }
    pages["group"] = [LDAPPage((first,), b""), LDAPPage((continuation,), b"")]
    session = FixtureSession(pages)
    result = asyncio.run(collector(repo, deployment, FixtureFactory(session)).collect(context()))
    assert result.issues == ()
    range_calls = [call for call in session.calls if "member;range=1500-*" in call[3]]
    assert len(range_calls) == 1
    stored = repo.connection.execute(
        "SELECT attributes_json FROM ad_entities WHERE entity_kind='group'"
    ).fetchone()[0]
    assert "member;range=0-1499" in stored
    assert "member;range=1500-*" in stored
    repo.close()


@pytest.mark.parametrize("mode", ["empty", "malformed", "repeat"])
def test_large_group_range_partial_and_loop_limits_are_disclosed(tmp_path: Path, mode: str) -> None:
    repo, deployment = repository(tmp_path)
    pages = pages_from_fixture()
    first = dict(fixture()["group"])
    first.pop("member;range=0-*")
    first["member;range=0-1"] = ["CN=Member0,DC=example,DC=invalid"]
    if mode == "empty":
        continuation = LDAPPage((), b"")
    elif mode == "malformed":
        continuation = LDAPPage(
            (
                {
                    "distinguishedName": first["distinguishedName"],
                    "objectGUID": first["objectGUID"],
                },
            ),
            b"",
        )
    else:
        repeated = {
            "distinguishedName": first["distinguishedName"],
            "objectGUID": first["objectGUID"],
            "member;range=2-3": ["CN=Member2,DC=example,DC=invalid"],
        }
        continuation = LDAPPage((repeated,), b"")
    actions = [LDAPPage((first,), b""), continuation]
    if mode == "repeat":
        actions.append(continuation)
    pages["group"] = actions
    result = asyncio.run(
        collector(repo, deployment, FixtureFactory(FixtureSession(pages))).collect(context())
    )
    expected = "ad_group_range_limit" if mode == "repeat" else "ad_group_range_partial"
    assert expected in [issue.category for issue in result.issues]
    repo.close()


def test_insufficient_and_failed_queries_are_partial_not_fatal(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    pages: dict[str, list[LDAPPage | BaseException]] = {
        key: list(value) for key, value in pages_from_fixture().items()
    }
    pages["computer"] = [ADAuthorizationError("fixture")]
    pages["trust"] = [ADCollectionError("fixture")]
    result = asyncio.run(
        collector(repo, deployment, FixtureFactory(FixtureSession(pages))).collect(context())
    )
    assert [issue.category for issue in result.issues] == [
        "ad_insufficient_access",
        "ad_partial_query",
    ]
    assert result.item_count == 7
    repo.close()


@pytest.mark.parametrize(
    "failure",
    [
        CollectorAuthenticationError("expired credential"),
        RetryableCollectorError("timeout"),
    ],
)
def test_expired_credential_and_connection_timeout_are_propagated(
    tmp_path: Path, failure: BaseException
) -> None:
    repo, deployment = repository(tmp_path)
    with pytest.raises(type(failure)):
        asyncio.run(collector(repo, deployment, FixtureFactory(failure)).collect(context()))
    assert repo.connection.execute("SELECT count(*) FROM ad_domains").fetchone()[0] == 0
    repo.close()


def test_missing_credential_rootdse_mismatch_and_missing_configuration_close_session(
    tmp_path: Path,
) -> None:
    repo, deployment = repository(tmp_path)
    session = FixtureSession(pages_from_fixture())
    instance = collector(repo, deployment, FixtureFactory(session))
    with pytest.raises(ADCollectionError, match="credential reference"):
        asyncio.run(instance.collect(context(reference=None)))

    mismatch = pages_from_fixture()
    mismatch["root"] = [
        LDAPPage(
            (
                {
                    "defaultNamingContext": ["DC=other,DC=invalid"],
                    "configurationNamingContext": ["CN=Configuration,DC=other,DC=invalid"],
                },
            ),
            b"",
        )
    ]
    wrong = FixtureSession(mismatch)
    with pytest.raises(ADCollectionError, match="does not match"):
        asyncio.run(collector(repo, deployment, FixtureFactory(wrong)).collect(context()))
    assert wrong.closed

    missing = pages_from_fixture()
    missing["root"] = [LDAPPage(({"defaultNamingContext": ["DC=example,DC=invalid"]},), b"")]
    absent = FixtureSession(missing)
    with pytest.raises(ADCollectionError, match="configuration naming"):
        asyncio.run(collector(repo, deployment, FixtureFactory(absent)).collect(context()))
    assert absent.closed

    empty = FixtureSession({"root": [LDAPPage((), b"")]})
    with pytest.raises(ADCollectionError, match="did not return"):
        asyncio.run(collector(repo, deployment, FixtureFactory(empty)).collect(context()))
    assert empty.closed
    repo.close()


def test_cancellation_repeated_cookie_entry_limit_and_malformed_entry(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    instance = collector(repo, deployment, FixtureFactory(FixtureSession({})))
    cancelled = context()
    cancelled.cancellation.set()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            instance._run_query(
                FixtureSession({}), QuerySpec("x", "b", "f", "base", ("name",), "name"), cancelled
            )
        )

    repeat = FixtureSession({"root": [LDAPPage(({"name": "x"},), b"same"), LDAPPage((), b"same")]})
    with pytest.raises(ADCollectionError, match="cookie repeated"):
        asyncio.run(
            instance._run_query(
                repeat, QuerySpec("root", "", "f", "base", ("name",), "name"), context()
            )
        )

    limited = collector(repo, deployment, FixtureFactory(FixtureSession({})), max_entries=1)
    records, issues = asyncio.run(
        limited._run_query(
            FixtureSession({"root": [LDAPPage(({"name": "a"}, {"name": "b"}), b"next")]}),
            QuerySpec("root", "", "f", "base", ("name",), "name"),
            context(),
        )
    )
    assert len(records) == 1
    assert issues[0].category == "ad_entry_limit"

    malformed_records, malformed_issues = asyncio.run(
        instance._run_query(
            FixtureSession({"root": [LDAPPage(({"description": "none"},), b"")]}),
            QuerySpec("root", "", "f", "base", ("description",), "name"),
            context(),
        )
    )
    assert malformed_records == []
    assert malformed_issues[0].category == "ad_malformed_entry"
    repo.close()


def test_collection_cancellation_after_root_closes_session(tmp_path: Path) -> None:
    repo, deployment = repository(tmp_path)
    stop = asyncio.Event()

    class CancellingSession(FixtureSession):
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
            page = await super().search(
                base,
                ldap_filter,
                scope,
                attributes,
                page_size=page_size,
                cookie=cookie,
            )
            if base == "":
                stop.set()
            return page

    session = CancellingSession(pages_from_fixture())
    cancelled_context = CollectorContext("192.168.50.10", REFERENCE, stop)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(collector(repo, deployment, FixtureFactory(session)).collect(cancelled_context))
    assert session.closed
    repo.close()


@pytest.mark.parametrize(
    "overrides",
    [
        {"transport": "ldap", "allow_plaintext_ldap": False},
        {"transport": "other"},
        {"page_size": 0},
        {"page_size": 1001},
        {"max_entries": 0},
        {"max_entries": 100001},
        {"documentation_groups": tuple(f"g{index}" for index in range(129))},
        {"documentation_groups": ("",)},
        {"documentation_groups": ("x" * 257,)},
    ],
)
def test_collector_configuration_is_strict(tmp_path: Path, overrides: dict[str, object]) -> None:
    repo, deployment = repository(tmp_path)
    with pytest.raises(ADCollectionError):
        collector(repo, deployment, FixtureFactory(FixtureSession({})), **overrides)
    repo.close()


def test_query_specs_group_filter_escaping_and_no_default_group_query() -> None:
    base = "DC=example,DC=invalid"
    config = "CN=Configuration,DC=example,DC=invalid"
    specs = _query_specs(base, config, ())
    assert len(specs) == 7
    assert all(spec.kind != "group" for spec in specs)
    specs = _query_specs(base, config, ("Doc*(Readers)",))
    assert specs[-1].kind == "group"
    assert "Doc\\2a\\28Readers\\29" in specs[-1].ldap_filter
    assert _escape_filter("a\\b\0") == r"a\5cb\00"


def test_sanitizer_handles_binary_scalar_sequence_unknown_and_forbidden() -> None:
    entry = {
        "objectGUID": b"\x01\x02",
        "name": "x" * 5000,
        "member": list(range(MAX_ATTRIBUTE_VALUES + 1)),
        "count": 2,
        "nothing": None,
        "custom": object(),
        "passwordHash": "forbidden",
        "madeUp": "ignored",
    }
    safe, filtered = _sanitize_entry(
        entry, ("objectGUID", "name", "member", "count", "nothing", "custom")
    )
    assert safe["objectGUID"] == "0102"
    assert len(cast(str, safe["name"])) == 4096
    assert len(cast(list[object], safe["member"])) == MAX_ATTRIBUTE_VALUES
    assert safe["count"] == 2
    assert safe["nothing"] is None
    assert isinstance(safe["custom"], str)
    assert filtered == 2
    assert _safe_value(("a",)) == ["a"]


def test_first_dn_and_server_role_helpers() -> None:
    assert _first({"name": ["first", "second"]}, "name") == "first"
    assert _first({"name": []}, "name") == "[]"
    assert _first({}, "name") is None
    assert _dn_to_domain("CN=X") is None
    assert _dn_to_domain("DC=Example,DC=Invalid") == "example.invalid"
    assert _server_roles({"servicePrincipalName": "KADMIN/dc"}) == (
        "domain_controller",
        "kerberos_admin",
    )
    assert _server_roles({"servicePrincipalName": [3, "OTHER/x"]}) == ("domain_controller",)


@pytest.mark.parametrize(
    ("transport", "raw", "expected"),
    [
        (
            "kerberos",
            '{"principal":"operator@EXAMPLE.INVALID","use_system_ccache":true}',
            ADCredentials("kerberos", "operator@EXAMPLE.INVALID"),
        ),
        (
            "ldaps",
            '{"username":"EXAMPLE\\\\operator","password":"synthetic-secret"}',
            ADCredentials("password", "EXAMPLE\\operator", "synthetic-secret"),
        ),
        (
            "ldap",
            '{"username":"operator@example.invalid","password":"synthetic-secret"}',
            ADCredentials("password", "operator@example.invalid", "synthetic-secret"),
        ),
    ],
)
def test_credential_profiles_are_transport_specific(
    transport: str, raw: str, expected: ADCredentials
) -> None:
    assert ADCredentials.from_secret(raw, transport) == expected


@pytest.mark.parametrize(
    ("transport", "raw"),
    [
        ("kerberos", "bad-json"),
        ("kerberos", "[]"),
        ("kerberos", '{"principal":"p"}'),
        ("kerberos", '{"principal":"","use_system_ccache":true}'),
        ("kerberos", '{"principal":"p","use_system_ccache":false}'),
        ("ldaps", '{"username":"u"}'),
        ("ldaps", '{"username":"","password":"p"}'),
        ("ldaps", '{"username":"u","password":""}'),
        ("other", '{"username":"u","password":"p"}'),
    ],
)
def test_invalid_credential_profiles_are_rejected(transport: str, raw: str) -> None:
    with pytest.raises(ADCollectionError, match="profile|fields|transport"):
        ADCredentials.from_secret(raw, transport)


def test_env_file_credential_resolution_requires_exact_safe_file(tmp_path: Path) -> None:
    path = tmp_path / "secrets.env"
    profile = '{"username":"operator","password":"synthetic-secret"}'
    path.write_text(f"AD_PROFILE={profile}\n")
    path.chmod(0o600)
    providers = {"fixture": {"type": "env_file", "path": str(path)}}
    assert resolve_ad_credentials(REFERENCE, providers, "ldaps").identity == "operator"
    path.chmod(0o400)
    with pytest.raises(ADCollectionError, match="unsafe"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")
    path.chmod(0o600)
    path.write_bytes(b"x" * (MAX_SECRET_BYTES + 1))
    with pytest.raises(ADCollectionError, match="size"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")
    path.write_bytes(b"\xff")
    with pytest.raises(ADCollectionError, match="UTF-8"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")
    path.write_text("OTHER=value\n")
    with pytest.raises(ADCollectionError, match="unavailable"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")
    path.unlink()
    with pytest.raises(ADCollectionError, match="unavailable"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")
    target = tmp_path / "target"
    target.write_text(profile)
    target.chmod(0o600)
    path.symlink_to(target)
    with pytest.raises(ADCollectionError, match="unsafe"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")


def test_command_credential_resolution_uses_stdin_and_maps_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider: dict[str, object] = {
        "type": "command",
        "executable": "/fixture/helper",
        "timeout_seconds": 2,
    }
    providers = {"fixture": provider}
    profile = '{"username":"operator","password":"synthetic-secret"}\n'
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def success(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(["helper"], 0, profile, "")

    monkeypatch.setattr(subprocess, "run", success)
    assert resolve_ad_credentials(REFERENCE, providers, "ldaps").identity == "operator"
    assert calls[0][0][0] == ["/fixture/helper"]
    assert calls[0][1]["input"] == "AD_PROFILE\n"
    assert calls[0][1]["env"] == {"PATH": "/usr/bin:/bin"}

    provider["timeout_seconds"] = True
    with pytest.raises(ADCollectionError, match="timeout"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")
    provider["timeout_seconds"] = 2
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(["helper"], 1, "", "secret"),
    )
    with pytest.raises(ADCollectionError, match="failed"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["helper"], 0, "x" * (MAX_SECRET_BYTES + 1), ""
        ),
    )
    with pytest.raises(ADCollectionError, match="failed"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")
    monkeypatch.setattr(
        subprocess, "run", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError())
    )
    with pytest.raises(ADCollectionError, match="failed"):
        resolve_ad_credentials(REFERENCE, providers, "ldaps")


def test_missing_and_unknown_credential_provider_are_rejected() -> None:
    with pytest.raises(ADCollectionError, match="unavailable"):
        resolve_ad_credentials(REFERENCE, {}, "ldaps")
    with pytest.raises(ADCollectionError, match="unsupported"):
        resolve_ad_credentials(REFERENCE, {"fixture": {"type": "vault"}}, "ldaps")


class FakeLDAPConnection:
    ok = True
    result_value: ClassVar[dict[str, object]] = {"result": 0}
    response_value: ClassVar[list[dict[str, object]]] = []
    failure: BaseException | None = None
    calls: ClassVar[list[tuple[tuple[object, ...], dict[str, object]]]] = []
    unbound = False

    @property
    def result(self) -> Mapping[str, object]:
        return type(self).result_value

    @property
    def response(self) -> Sequence[Mapping[str, object]]:
        return type(self).response_value

    def search(self, *args: object, **kwargs: object) -> bool:
        type(self).calls.append((args, kwargs))
        failure = type(self).failure
        if failure is not None:
            raise failure
        return type(self).ok

    def unbind(self) -> None:
        type(self).unbound = True


def test_ldap3_page_adapter_parses_entries_referrals_cookie_and_closes() -> None:
    connection = FakeLDAPConnection()
    type(connection).ok = True
    type(connection).failure = None
    type(connection).result_value = {
        "result": 0,
        "controls": {ad_module.LDAP_PAGED_RESULTS_OID: {"value": {"cookie": b"next"}}},
    }
    type(connection).response_value = [
        {"type": "searchResEntry", "dn": "CN=X", "attributes": {"name": ["X"]}},
        {"type": "searchResEntry", "dn": "CN=Bad", "attributes": "bad"},
        {"type": "searchResRef", "uri": ["ldap://one", "ldap://two"]},
        {"type": "searchResRef", "uri": "ldap://three"},
        {"type": "searchResDone"},
    ]
    session = _Ldap3Session(connection)
    page = asyncio.run(
        session.search("base", "filter", "subtree", ("name",), page_size=100, cookie=b"old")
    )
    assert page.entries == ({"name": ["X"], "distinguishedName": "CN=X"},)
    assert page.cookie == b"next"
    assert page.referrals == ("ldap://one", "ldap://two", "ldap://three")
    assert connection.calls[-1][1]["search_scope"] == ldap3.SUBTREE
    assert connection.calls[-1][1]["paged_cookie"] == b"old"
    asyncio.run(session.close())
    assert connection.unbound


@pytest.mark.parametrize("scope", ["base", "one", "subtree"])
def test_ldap3_page_scope_and_no_cookie(scope: str) -> None:
    connection = FakeLDAPConnection()
    type(connection).ok = True
    type(connection).failure = None
    type(connection).result_value = {
        "result": 0,
        "controls": {ad_module.LDAP_PAGED_RESULTS_OID: {"value": {"cookie": "bad"}}},
    }
    type(connection).response_value = []
    page = _Ldap3Session(connection)._search_sync("b", "f", scope, (), 10, b"")
    assert page.cookie == b""
    assert connection.calls[-1][1]["paged_cookie"] is None


@pytest.mark.parametrize(
    "controls",
    ["invalid", {ad_module.LDAP_PAGED_RESULTS_OID: "invalid"}],
)
def test_ldap3_page_ignores_malformed_controls(controls: object) -> None:
    connection = FakeLDAPConnection()
    type(connection).ok = True
    type(connection).failure = None
    type(connection).result_value = {"result": 0, "controls": controls}
    type(connection).response_value = []
    assert _Ldap3Session(connection)._search_sync("b", "f", "base", (), 10, b"").cookie == b""


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (49, CollectorAuthenticationError),
        (50, ADAuthorizationError),
        (53, ADAuthorizationError),
        (1, ADCollectionError),
    ],
)
def test_ldap3_page_result_failure_mapping(code: int, expected: type[BaseException]) -> None:
    connection = FakeLDAPConnection()
    type(connection).ok = False
    type(connection).failure = None
    type(connection).result_value = {"result": code}
    with pytest.raises(expected):
        _Ldap3Session(connection)._search_sync("b", "f", "base", (), 10, b"")


class LDAPSocketTimeout(Exception):
    pass


class LDAPInvalidCredentialsResult(Exception):
    pass


class LDAPInsufficientAccessRightsResult(Exception):
    pass


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (LDAPInvalidCredentialsResult(), CollectorAuthenticationError),
        (RuntimeError("ticket expired"), CollectorAuthenticationError),
        (LDAPInsufficientAccessRightsResult(), ADAuthorizationError),
        (LDAPSocketTimeout(), RetryableCollectorError),
        (RuntimeError("other"), ADCollectionError),
    ],
)
def test_ldap3_page_exception_mapping(
    failure: BaseException, expected: type[BaseException]
) -> None:
    connection = FakeLDAPConnection()
    type(connection).failure = failure
    with pytest.raises(expected):
        _Ldap3Session(connection)._search_sync("b", "f", "base", (), 10, b"")


def test_ldap3_factory_strict_ldaps_and_kerberos_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    servers: list[tuple[tuple[object, ...], dict[str, object]]] = []
    connections: list[tuple[object, dict[str, object]]] = []
    tls_values: list[dict[str, object]] = []

    def tls(**kwargs: object) -> object:
        tls_values.append(kwargs)
        return "tls"

    def server(*args: object, **kwargs: object) -> object:
        servers.append((args, kwargs))
        return object()

    def connection(server_value: object, **kwargs: object) -> FakeLDAPConnection:
        connections.append((server_value, kwargs))
        return FakeLDAPConnection()

    monkeypatch.setattr(ldap3, "Tls", tls)
    monkeypatch.setattr(ldap3, "Server", server)
    monkeypatch.setattr(ldap3, "Connection", connection)
    factory = Ldap3SessionFactory()
    asyncio.run(
        factory.connect(
            "192.168.50.10",
            "dc1.example.invalid",
            "ldaps",
            ADCredentials("password", "operator", "secret"),
            timeout=3,
        )
    )
    assert servers[0][1]["port"] == 636
    assert tls_values[0] == {
        "validate": ssl.CERT_REQUIRED,
        "valid_names": ["dc1.example.invalid"],
    }
    assert connections[0][1]["password"] == "secret"
    assert connections[0][1]["auto_referrals"] is False

    asyncio.run(
        factory.connect(
            "192.168.50.10",
            "dc1.example.invalid",
            "kerberos",
            ADCredentials("kerberos", "operator@EXAMPLE.INVALID"),
            timeout=3,
        )
    )
    assert servers[1][1]["port"] == 389
    assert servers[1][1]["tls"] is None
    assert connections[1][1]["authentication"] == ldap3.SASL
    assert connections[1][1]["sasl_mechanism"] == ldap3.KERBEROS
    assert connections[1][1]["sasl_credentials"] == (None, "dc1.example.invalid")


def test_ldap3_factory_rejects_profile_mismatch_and_maps_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ldap3, "Server", lambda *_args, **_kwargs: object())
    with pytest.raises(ADCollectionError, match="Kerberos transport"):
        Ldap3SessionFactory._connect_sync(
            "192.168.50.10", "dc", "kerberos", ADCredentials("password", "u", "p"), 2
        )
    with pytest.raises(ADCollectionError, match="password credential"):
        Ldap3SessionFactory._connect_sync(
            "192.168.50.10", "dc", "ldaps", ADCredentials("kerberos", "p"), 2
        )

    def fail(*_args: object, **_kwargs: object) -> object:
        raise LDAPSocketTimeout()

    monkeypatch.setattr(ldap3, "Connection", fail)
    with pytest.raises(RetryableCollectorError):
        Ldap3SessionFactory._connect_sync(
            "192.168.50.10", "dc", "ldap", ADCredentials("password", "u", "p"), 2
        )
