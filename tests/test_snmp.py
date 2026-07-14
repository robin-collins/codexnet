"""Mock-only SNMP transport, profile, credential, and normalization tests."""

from __future__ import annotations

import asyncio
import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from field_discovery import snmp
from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CollectorIssue,
    CredentialReference,
    RetryableCollectorError,
)
from field_discovery.redaction import REDACTED, Redactor
from field_discovery.repository import Repository
from field_discovery.snmp import (
    BASE_OID_REGISTRY,
    DEFAULT_OID_REGISTRY,
    INFRASTRUCTURE_OID_REGISTRY,
    MAX_SECRET_BYTES,
    MAX_VALUE_CHARS,
    OidField,
    PySnmpTransport,
    SnmpCollector,
    SnmpConfigurationError,
    SnmpProtocolError,
    SnmpResponse,
    SnmpTransport,
    SnmpV2cCredential,
    SnmpV3Credential,
    SnmpVarBind,
    normalize_varbinds,
    parse_snmp_credential,
    resolve_secret,
)

NOW = datetime(2026, 7, 15, 3, 0, tzinfo=UTC)


def create_repository(tmp_path: Path) -> tuple[Repository, int]:
    root = tmp_path / "data"
    root.mkdir()
    repository = Repository.open(root / "discovery.db", data_root=root)
    deployment = repository.upsert_deployment("fixture", "Fixture", NOW.isoformat())
    return repository, deployment


def profile(value: dict[str, object]) -> str:
    return json.dumps(value, separators=(",", ":"))


def test_v3_credentials_are_secure_by_default_and_secret_free_in_repr() -> None:
    credential = parse_snmp_credential(
        profile(
            {
                "username": "collector",
                "auth_key": "auth-secret",
                "priv_key": "priv-secret",
                "auth_protocol": "sha512",
                "priv_protocol": "aes256",
            }
        ),
        protocol="v3",
        allow_insecure_v2c=False,
    )
    assert isinstance(credential, SnmpV3Credential)
    assert credential.secrets == ("auth-secret", "priv-secret")
    assert credential.auth_protocol == "sha512"
    assert "secret" not in repr(credential)
    auth_only = parse_snmp_credential(
        profile({"username": "collector", "auth_key": "12345678"}),
        protocol="v3",
        allow_insecure_v2c=False,
    )
    assert isinstance(auth_only, SnmpV3Credential)
    assert auth_only.priv_protocol is None


def test_v2c_requires_explicit_opt_in_and_never_has_a_default_community() -> None:
    with pytest.raises(SnmpConfigurationError, match="explicit"):
        parse_snmp_credential(
            profile({"community": "site-value"}),
            protocol="v2c",
            allow_insecure_v2c=False,
        )
    credential = parse_snmp_credential(
        profile({"community": "site-value"}),
        protocol="v2c",
        allow_insecure_v2c=True,
    )
    assert isinstance(credential, SnmpV2cCredential)
    assert credential.secrets == ("site-value",)
    assert "site-value" not in repr(credential)


@pytest.mark.parametrize(
    ("raw", "protocol", "message"),
    [
        ("not-json", "v3", "must be JSON"),
        ("[]", "v3", "JSON object"),
        (profile({"community": "x", "extra": "x"}), "v2c", "only community"),
        (profile({"community": ""}), "v2c", "non-empty"),
        (profile({"username": "x"}), "v3", "requires username"),
        (profile({"username": "", "auth_key": "12345678"}), "v3", "username"),
        (profile({"username": "x", "auth_key": "short"}), "v3", "eight"),
        (
            profile({"username": "x", "auth_key": "12345678", "auth_protocol": []}),
            "v3",
            "auth_protocol",
        ),
        (
            profile({"username": "x", "auth_key": "12345678", "priv_key": "short"}),
            "v3",
            "priv_key",
        ),
        (
            profile(
                {
                    "username": "x",
                    "auth_key": "12345678",
                    "priv_protocol": "aes128",
                }
            ),
            "v3",
            "requires priv_key",
        ),
        (
            profile(
                {
                    "username": "x",
                    "auth_key": "12345678",
                    "priv_key": "12345678",
                    "priv_protocol": [],
                }
            ),
            "v3",
            "priv_protocol",
        ),
        (profile({"username": "x", "auth_key": "12345678"}), "v1", "protocol"),
    ],
)
def test_invalid_credential_profiles_fail_without_echoing_values(
    raw: str, protocol: str, message: str
) -> None:
    with pytest.raises(SnmpConfigurationError, match=message) as caught:
        parse_snmp_credential(raw, protocol=protocol, allow_insecure_v2c=True)
    assert "12345678" not in str(caught.value)


def test_env_file_secret_resolution_is_restricted_and_exact(tmp_path: Path) -> None:
    path = tmp_path / "secrets.env"
    path.write_text('# ignored\nOTHER=value\nSNMP_PROFILE={"username":"u"}\n')
    path.chmod(0o600)
    reference = CredentialReference("site", "SNMP_PROFILE")
    providers = {"site": {"type": "env_file", "path": str(path)}}
    assert asyncio.run(resolve_secret(reference, providers)) == '{"username":"u"}'

    path.write_text("SNMP_PROFILE=one\nSNMP_PROFILE=two\n")
    with pytest.raises(SnmpConfigurationError, match="duplicate"):
        asyncio.run(resolve_secret(reference, providers))
    path.write_text("malformed\n")
    with pytest.raises(SnmpConfigurationError, match="malformed"):
        asyncio.run(resolve_secret(reference, providers))
    path.write_text("OTHER=value\n")
    with pytest.raises(SnmpConfigurationError, match="missing or empty"):
        asyncio.run(resolve_secret(reference, providers))
    path.write_text("SNMP_PROFILE=\n")
    with pytest.raises(SnmpConfigurationError, match="missing or empty"):
        asyncio.run(resolve_secret(reference, providers))


def test_env_file_rejects_unsafe_files(tmp_path: Path) -> None:
    reference = CredentialReference("site", "SNMP_PROFILE")

    def provider(path: Path) -> dict[str, dict[str, object]]:
        return {"site": {"type": "env_file", "path": str(path)}}

    missing = tmp_path / "missing"
    with pytest.raises(SnmpConfigurationError, match="unavailable"):
        asyncio.run(resolve_secret(reference, provider(missing)))
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(SnmpConfigurationError, match="regular"):
        asyncio.run(resolve_secret(reference, provider(directory)))
    real = tmp_path / "real"
    real.write_text("SNMP_PROFILE=value")
    real.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(SnmpConfigurationError, match="non-symlink"):
        asyncio.run(resolve_secret(reference, provider(link)))
    real.chmod(0o640)
    with pytest.raises(SnmpConfigurationError, match="0600"):
        asyncio.run(resolve_secret(reference, provider(real)))
    real.chmod(0o600)
    real.write_bytes(b"x" * (MAX_SECRET_BYTES + 1))
    with pytest.raises(SnmpConfigurationError, match="size"):
        asyncio.run(resolve_secret(reference, provider(real)))
    real.write_bytes(b"SNMP_PROFILE=\xff")
    with pytest.raises(SnmpConfigurationError, match="UTF-8"):
        asyncio.run(resolve_secret(reference, provider(real)))


def test_env_file_read_failure_is_generic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "secret"
    path.write_text("KEY=value")
    path.chmod(0o600)

    def fail(_descriptor: int, _size: int) -> bytes:
        raise OSError("synthetic")

    monkeypatch.setattr(snmp.os, "read", fail)
    with pytest.raises(SnmpConfigurationError, match="cannot be read"):
        asyncio.run(
            resolve_secret(
                CredentialReference("site", "KEY"),
                {"site": {"type": "env_file", "path": str(path)}},
            )
        )


def test_env_file_open_race_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "secret"
    path.write_text("KEY=value")
    path.chmod(0o600)
    provider = {"site": {"type": "env_file", "path": str(path)}}

    def fail_open(*_args: object, **_kwargs: object) -> int:
        raise OSError("synthetic")

    monkeypatch.setattr(snmp.os, "open", fail_open)
    with pytest.raises(SnmpConfigurationError, match="cannot be read"):
        asyncio.run(resolve_secret(CredentialReference("site", "KEY"), provider))

    monkeypatch.undo()
    real_fstat = snmp.os.fstat

    def unsafe_fstat(descriptor: int) -> object:
        result = real_fstat(descriptor)
        values = list(result)
        values[0] = stat.S_IFREG | 0o640
        return snmp.os.stat_result(values)

    monkeypatch.setattr(snmp.os, "fstat", unsafe_fstat)
    with pytest.raises(SnmpConfigurationError, match="cannot be read"):
        asyncio.run(resolve_secret(CredentialReference("site", "KEY"), provider))


def test_secret_provider_validation_errors_are_generic() -> None:
    reference = CredentialReference("site", "SNMP_PROFILE")
    cases = [
        ({}, "unknown provider"),
        ({"site": {"type": "env_file", "path": 1}}, "path is invalid"),
        ({"site": {"type": "command", "executable": 1}}, "provider is invalid"),
        ({"site": {"type": "unsupported"}}, "type is unsupported"),
    ]
    for providers, message in cases:
        with pytest.raises(SnmpConfigurationError, match=message):
            asyncio.run(resolve_secret(reference, providers))


class FakeProcess:
    def __init__(self, stdout: bytes, returncode: int = 0, *, block: bool = False) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.block = block
        self.input: bytes | None = None
        self.killed = False
        self.waited = False

    async def communicate(self, value: bytes) -> tuple[bytes, bytes]:
        self.input = value
        if self.block:
            await asyncio.Event().wait()
        return self.stdout, b""

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        self.waited = True
        return self.returncode


def test_command_secret_uses_stdin_not_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess(b"resolved-value\n")
    captured: tuple[object, ...] = ()

    async def create(*args: object, **_kwargs: object) -> FakeProcess:
        nonlocal captured
        captured = args
        return process

    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", create)
    reference = CredentialReference("helper", "SNMP_PROFILE")
    providers = {
        "helper": {"type": "command", "executable": "/fixture/helper", "timeout_seconds": 1}
    }
    assert asyncio.run(resolve_secret(reference, providers)) == "resolved-value"
    assert captured == ("/fixture/helper",)
    assert process.input == b"SNMP_PROFILE\n"


@pytest.mark.parametrize(
    ("stdout", "returncode", "message"),
    [
        (b"", 0, "no usable"),
        (b"value", 1, "no usable"),
        (b"x" * (MAX_SECRET_BYTES + 1), 0, "no usable"),
        (b"\n", 0, "no usable"),
        (b"\xff", 0, "UTF-8"),
    ],
)
def test_command_secret_rejects_bad_output(
    monkeypatch: pytest.MonkeyPatch, stdout: bytes, returncode: int, message: str
) -> None:
    async def create(*_args: object, **_kwargs: object) -> FakeProcess:
        return FakeProcess(stdout, returncode)

    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", create)
    with pytest.raises(SnmpConfigurationError, match=message):
        asyncio.run(
            resolve_secret(
                CredentialReference("helper", "KEY"),
                {"helper": {"type": "command", "executable": "/helper", "timeout_seconds": 1}},
            )
        )


def test_command_secret_handles_launch_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fail(*_args: object, **_kwargs: object) -> FakeProcess:
        raise OSError("synthetic")

    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", fail)
    provider = {"helper": {"type": "command", "executable": "/helper", "timeout_seconds": 1}}
    with pytest.raises(SnmpConfigurationError, match="failed"):
        asyncio.run(resolve_secret(CredentialReference("helper", "KEY"), provider))

    async def launch_timeout(*_args: object, **_kwargs: object) -> FakeProcess:
        raise TimeoutError

    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", launch_timeout)
    with pytest.raises(SnmpConfigurationError, match="failed"):
        asyncio.run(resolve_secret(CredentialReference("helper", "KEY"), provider))

    process = FakeProcess(b"never", block=True)

    async def create(*_args: object, **_kwargs: object) -> FakeProcess:
        return process

    async def immediate_timeout(_awaitable: object, *, timeout: float) -> bytes:
        del timeout
        cast(Any, _awaitable).close()
        raise TimeoutError

    monkeypatch.setattr(snmp.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(snmp.asyncio, "wait_for", immediate_timeout)
    with pytest.raises(SnmpConfigurationError, match="failed"):
        asyncio.run(resolve_secret(CredentialReference("helper", "KEY"), provider))
    assert process.killed and process.waited


def test_oid_registry_contains_required_base_domains() -> None:
    facts = {field.fact_type for field in BASE_OID_REGISTRY}
    assert any(name.startswith("snmp.system.") for name in facts)
    assert any(name.startswith("snmp.interface.") for name in facts)
    assert any(name.startswith("snmp.address.") for name in facts)
    assert any(name.startswith("snmp.lldp.") for name in facts)
    assert len({field.oid for field in BASE_OID_REGISTRY}) == len(BASE_OID_REGISTRY)


def fixture_varbinds(name: str) -> tuple[SnmpVarBind, ...]:
    document = json.loads((Path(__file__).parent / "fixtures" / "snmp" / name).read_text())
    assert "synthetic" in document["fixture"].casefold()
    return tuple(SnmpVarBind(item["oid"], item["value"]) for item in document["varbinds"])


def facts_by_type(name: str) -> dict[str, list[dict[str, object]]]:
    facts, issues = normalize_varbinds(fixture_varbinds(name), DEFAULT_OID_REGISTRY, max_unknown=0)
    assert issues == ()
    output: dict[str, list[dict[str, object]]] = {}
    for fact_type, value in facts:
        output.setdefault(fact_type, []).append(value)
    return output


def test_infrastructure_registry_is_unique_and_covers_every_required_domain() -> None:
    facts = {field.fact_type for field in INFRASTRUCTURE_OID_REGISTRY}
    for prefix in (
        "snmp.bridge.",
        "snmp.neighbor.",
        "snmp.vlan.",
        "snmp.poe.",
        "snmp.environment.",
        "snmp.ups.",
        "snmp.printer.",
        "snmp.firmware.",
    ):
        assert any(fact.startswith(prefix) for fact in facts)
    assert len({field.oid for field in DEFAULT_OID_REGISTRY}) == len(DEFAULT_OID_REGISTRY)


def test_synthetic_switch_fixtures_normalize_bridge_neighbor_vlan_poe_and_versions() -> None:
    cisco = facts_by_type("cisco-switch.json")
    assert cisco["snmp.bridge.mac"][0]["value"] == "02:00:00:00:00:0a"
    assert cisco["snmp.bridge.status"][0]["label"] == "learned"
    assert cisco["snmp.neighbor.ipv4"][0]["value"] == "192.0.2.10"
    assert cisco["snmp.neighbor.mapping_type"][0]["label"] == "dynamic"
    assert cisco["snmp.poe.port.detection_status"][0]["label"] == "delivering_power"
    assert cisco["snmp.poe.main.power_budget"][0] == {
        "index": "1",
        "value": 370,
        "unit": "W",
    }
    assert cisco["snmp.firmware.revision"][0]["value"] == "fixture-firmware-1.2.3"
    assert cisco["snmp.software.revision"][0]["value"] == "fixture-software-4.5.6"
    assert not any("vulnerab" in fact.casefold() for fact in cisco)

    aruba = facts_by_type("aruba-switch.json")
    assert aruba["snmp.vlan.name"][0] == {"index": "10", "value": "Fixture-Users"}
    assert aruba["snmp.vlan.egress_ports"][0]["value"] == "c000"
    assert aruba["snmp.vlan.forbidden_ports"][0]["value"] == "0000"
    assert aruba["snmp.vlan.untagged_ports"][0]["value"] == "8000"
    assert aruba["snmp.vlan.row_status"][0]["label"] == "active"


def test_synthetic_ups_fixture_preserves_native_units_and_enum_meaning() -> None:
    facts = facts_by_type("ups.json")
    assert facts["snmp.ups.battery.status"][0] == {
        "index": "",
        "value": 2,
        "label": "normal",
    }
    assert facts["snmp.ups.battery.seconds_on_battery"][0]["unit"] == "s"
    assert facts["snmp.ups.battery.runtime_remaining"][0]["unit"] == "min"
    assert facts["snmp.ups.battery.charge_remaining"][0] == {
        "index": "",
        "value": 97,
        "unit": "%",
    }
    assert facts["snmp.ups.battery.voltage"][0]["unit"] == "0.1 V DC"
    assert facts["snmp.ups.battery.current"][0]["unit"] == "0.1 A DC"
    assert facts["snmp.ups.battery.temperature"][0]["unit"] == "°C"


def test_synthetic_printer_fixture_preserves_counts_units_and_unknown_sentinels() -> None:
    facts = facts_by_type("printer.json")
    assert facts["snmp.printer.marker.life_count"][0]["value"] == 12345
    assert facts["snmp.printer.marker.counter_unit"][0] == {
        "index": "1.1",
        "value": 7,
        "label": "impressions",
    }
    assert facts["snmp.printer.supply.unit"][0] == {
        "index": "1.1",
        "value": 19,
        "label": "percent",
    }
    assert facts["snmp.printer.supply.maximum_capacity"][0]["value"] == 100
    unknown_capacity = facts["snmp.printer.supply.maximum_capacity"][1]
    assert unknown_capacity == {
        "index": "1.2",
        "value": None,
        "value_status": "unknown",
        "raw_value": "-2",
    }
    some_remaining = facts["snmp.printer.supply.level"][1]
    assert some_remaining["value"] is None
    assert some_remaining["value_status"] == "some_remaining"
    assert some_remaining["raw_value"] == "-3"


def test_synthetic_environment_fixture_preserves_scale_precision_unit_and_time() -> None:
    facts = facts_by_type("environment.json")
    assert facts["snmp.environment.sensor.type"][0]["label"] == "celsius"
    assert facts["snmp.environment.sensor.scale"][0]["label"] == "units"
    assert facts["snmp.environment.sensor.precision"][0]["unit"] == "decimal_places"
    assert facts["snmp.environment.sensor.value"][0]["value"] == 245
    assert facts["snmp.environment.sensor.units_display"][0]["value"] == "degrees C"
    assert facts["snmp.environment.sensor.timestamp"][0] == {
        "index": "100",
        "value": 7200,
        "unit": "centiseconds",
    }


def test_missing_and_unknown_enum_values_are_tolerated_without_inference() -> None:
    facts, issues = normalize_varbinds((), DEFAULT_OID_REGISTRY, max_unknown=0)
    assert facts == () and issues == ()
    facts, issues = normalize_varbinds(
        (
            SnmpVarBind("1.3.6.1.2.1.33.1.2.1.0", "99"),
            SnmpVarBind("1.3.6.1.2.1.17.7.1.4.3.1.2.10", "not-a-bitmap"),
        ),
        DEFAULT_OID_REGISTRY,
        max_unknown=0,
    )
    assert facts == (("snmp.ups.battery.status", {"index": "", "value": 99}),)
    assert [issue.category for issue in issues] == ["invalid_value"]


def test_transport_protocol_stub_has_no_runtime_behavior() -> None:
    result = asyncio.run(
        SnmpTransport.collect(
            cast(Any, object()),
            "192.0.2.1",
            SnmpV2cCredential("explicit"),
            scalar_oids=(),
            table_oids=(),
            max_table_rows=1,
            timeout_seconds=1,
            cancellation=asyncio.Event(),
        )
    )
    assert result is None


def test_normalization_handles_known_unknown_unsupported_invalid_and_limits() -> None:
    registry = (
        OidField("1.1.0", "text"),
        OidField("1.2", "integer", True, "integer"),
        OidField("1.3", "ipv4", True, "ipv4"),
        OidField("1.4", "mac", True, "mac"),
        OidField("1.5.0", "oid", value_kind="oid"),
        OidField("1.6.0", "bad_kind", value_kind="other"),
    )
    secret = "hidden-value"
    varbinds = (
        SnmpVarBind("1.1.0", secret + "x" * (MAX_VALUE_CHARS + 10)),
        SnmpVarBind("1.2.7", "42"),
        SnmpVarBind("1.3.7", "192.0.2.1"),
        SnmpVarBind("1.4.7", "00-11-22-AA-BB-CC"),
        SnmpVarBind("1.5.0", ".1.3.6"),
        SnmpVarBind("1.6.0", "x"),
        SnmpVarBind("1.2.8", "bad"),
        SnmpVarBind("1.3.8", "bad"),
        SnmpVarBind("1.4.8", "bad"),
        SnmpVarBind("1.5.0", "bad.oid"),
        SnmpVarBind("9.1", secret),
        SnmpVarBind("9.2", "not retained"),
        SnmpVarBind("9.3", "unsupported", True),
    )
    facts, issues = normalize_varbinds(
        varbinds, registry, max_unknown=1, redactor=Redactor([secret])
    )
    by_type = {fact_type: value for fact_type, value in facts}
    assert by_type["text"]["value"].startswith(REDACTED)
    assert len(cast(str, by_type["text"]["value"])) <= MAX_VALUE_CHARS
    assert by_type["integer"] == {"index": "7", "value": 42}
    assert by_type["ipv4"]["value"] == "192.0.2.1"
    assert by_type["mac"]["value"] == "00:11:22:aa:bb:cc"
    assert by_type["oid"]["value"] == "1.3.6"
    assert by_type["snmp.raw.unknown"]["value"] == REDACTED
    categories = [issue.category for issue in issues]
    assert categories.count("invalid_value") == 5
    assert "unsupported_oid" in categories
    assert "unknown_oid_limit" in categories


def test_normalization_can_drop_all_unknown_values() -> None:
    facts, issues = normalize_varbinds((SnmpVarBind("9.9", "x"),), (), max_unknown=0)
    assert facts == ()
    assert issues == (CollectorIssue("unknown_oid_limit", "unknown OID retention limit reached"),)
    facts, issues = normalize_varbinds(
        (SnmpVarBind("1.1.0", "known"),), (OidField("1.1.0", "known"),), max_unknown=1
    )
    assert facts == (("known", {"index": "", "value": "known"}),)
    assert issues == ()


class PrettyValue:
    def __init__(self, value: str, *, class_name: str = "PrettyValue") -> None:
        self.value = value
        self._class_name = class_name

    def prettyPrint(self) -> str:
        return self.value


def response(
    *, indication: object = None, status: object = 0, values: tuple[tuple[str, object], ...] = ()
) -> tuple[object, object, int, tuple[tuple[str, object], ...]]:
    return indication, status, 0, values


@pytest.mark.parametrize(
    ("indication", "status", "exception"),
    [
        ("authentication failure", 0, CollectorAuthenticationError),
        ("unknown user", 0, CollectorAuthenticationError),
        ("wrong digest", 0, CollectorAuthenticationError),
        ("timeout", 0, RetryableCollectorError),
        (None, "authorizationError", CollectorAuthenticationError),
        (None, "noAccess", CollectorAuthenticationError),
        (None, "genErr", SnmpProtocolError),
    ],
)
def test_response_error_classification(
    indication: object, status: object, exception: type[Exception]
) -> None:
    with pytest.raises(exception):
        snmp._response_varbinds(response(indication=indication, status=status))


def test_response_varbind_conversion_marks_unsupported() -> None:
    class NoSuchObject:
        def prettyPrint(self) -> str:
            return "No Such Object"

    output = snmp._response_varbinds(
        response(values=(("1.2.3", PrettyValue("value")), ("1.2.4", NoSuchObject())))
    )
    assert output == [
        SnmpVarBind("1.2.3", "value", False),
        SnmpVarBind("1.2.4", "No Such Object", True),
    ]


def test_pysnmp_auth_builds_v3_and_explicit_v2c() -> None:
    v2c = snmp._pysnmp_auth(SnmpV2cCredential("explicit"))
    assert v2c.message_processing_model == 1
    v3 = snmp._pysnmp_auth(SnmpV3Credential("user", "auth-pass", "sha224", "priv-pass", "aes192"))
    assert v3.userName == "user"
    auth_only = snmp._pysnmp_auth(SnmpV3Credential("user", "auth-pass", "sha384"))
    assert auth_only.security_level == "authNoPriv"


class FakeDispatcher:
    def __init__(self) -> None:
        self.closed = False

    def close_dispatcher(self) -> None:
        self.closed = True


class FakeEngine:
    last: FakeEngine | None = None

    def __init__(self, *, dispatcher: bool = True) -> None:
        self.transport_dispatcher = FakeDispatcher() if dispatcher else None
        FakeEngine.last = self


class FakeTarget:
    @staticmethod
    async def create(*_args: object, **_kwargs: object) -> object:
        return object()


def patch_transport_primitives(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(snmp, "SnmpEngine", FakeEngine)
    monkeypatch.setattr(snmp, "UdpTransportTarget", FakeTarget)
    monkeypatch.setattr(snmp, "ObjectIdentity", lambda value: value)
    monkeypatch.setattr(snmp, "ObjectType", lambda value: value)
    monkeypatch.setattr(snmp, "ContextData", lambda: object())
    monkeypatch.setattr(snmp, "_pysnmp_auth", lambda _credential: object())


def test_pysnmp_transport_get_walk_and_global_table_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_transport_primitives(monkeypatch)

    async def get(*_args: object, **_kwargs: object) -> tuple[object, object, int, tuple[Any, ...]]:
        return response(values=(("1.1.0", PrettyValue("system")),))

    async def walk(*_args: object, **_kwargs: object) -> Any:
        yield response(values=(("1.2.1", PrettyValue("one")), ("1.2.2", PrettyValue("two"))))

    monkeypatch.setattr(snmp, "get_cmd", get)
    monkeypatch.setattr(snmp, "bulk_walk_cmd", walk)
    result = asyncio.run(
        PySnmpTransport().collect(
            "192.0.2.1",
            SnmpV2cCredential("explicit"),
            scalar_oids=("1.1.0",),
            table_oids=("1.2", "1.3"),
            max_table_rows=1,
            timeout_seconds=1,
            cancellation=asyncio.Event(),
        )
    )
    assert result.varbinds == (
        SnmpVarBind("1.1.0", "system"),
        SnmpVarBind("1.2.1", "one"),
    )
    assert result.truncated
    assert result.issues[0].category == "table_limit"
    assert cast(FakeDispatcher, cast(FakeEngine, FakeEngine.last).transport_dispatcher).closed


def test_pysnmp_transport_empty_scalars_complete_walk_and_no_dispatcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_transport_primitives(monkeypatch)
    monkeypatch.setattr(snmp, "SnmpEngine", lambda: FakeEngine(dispatcher=False))

    async def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("scalar get called")

    async def walk(*_args: object, **_kwargs: object) -> Any:
        yield response(values=(("1.2.1", PrettyValue("one")),))

    monkeypatch.setattr(snmp, "get_cmd", forbidden)
    monkeypatch.setattr(snmp, "bulk_walk_cmd", walk)
    result = asyncio.run(
        PySnmpTransport().collect(
            "192.0.2.1",
            SnmpV2cCredential("explicit"),
            scalar_oids=(),
            table_oids=("1.2",),
            max_table_rows=2,
            timeout_seconds=1,
            cancellation=asyncio.Event(),
        )
    )
    assert result.varbinds == (SnmpVarBind("1.2.1", "one"),)
    assert not result.truncated and not result.issues


def test_pysnmp_transport_refuses_table_work_when_row_bound_is_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_transport_primitives(monkeypatch)

    async def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("network function called")
        yield None

    monkeypatch.setattr(snmp, "bulk_walk_cmd", forbidden)
    result = asyncio.run(
        PySnmpTransport().collect(
            "192.0.2.1",
            SnmpV2cCredential("explicit"),
            scalar_oids=(),
            table_oids=("1.2",),
            max_table_rows=0,
            timeout_seconds=1,
            cancellation=asyncio.Event(),
        )
    )
    assert result.truncated
    assert result.varbinds == ()


def test_pysnmp_transport_cancellation_and_error_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patch_transport_primitives(monkeypatch)

    async def get_ok(
        *_args: object, **_kwargs: object
    ) -> tuple[object, object, int, tuple[Any, ...]]:
        return response()

    async def walk(*_args: object, **_kwargs: object) -> Any:
        if False:
            yield None

    monkeypatch.setattr(snmp, "get_cmd", get_ok)
    monkeypatch.setattr(snmp, "bulk_walk_cmd", walk)
    stop = asyncio.Event()
    stop.set()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            PySnmpTransport().collect(
                "192.0.2.1",
                SnmpV2cCredential("explicit"),
                scalar_oids=("1.1",),
                table_oids=("1.2",),
                max_table_rows=1,
                timeout_seconds=1,
                cancellation=stop,
            )
        )

    async def unexpected(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("secret must not propagate")

    monkeypatch.setattr(snmp, "get_cmd", unexpected)
    with pytest.raises(RetryableCollectorError, match="transport failed"):
        asyncio.run(
            PySnmpTransport().collect(
                "192.0.2.1",
                SnmpV2cCredential("explicit"),
                scalar_oids=("1.1",),
                table_oids=(),
                max_table_rows=1,
                timeout_seconds=1,
                cancellation=asyncio.Event(),
            )
        )

    async def controlled(*_args: object, **_kwargs: object) -> object:
        raise SnmpProtocolError("safe")

    monkeypatch.setattr(snmp, "get_cmd", controlled)
    with pytest.raises(SnmpProtocolError):
        asyncio.run(
            PySnmpTransport().collect(
                "192.0.2.1",
                SnmpV2cCredential("explicit"),
                scalar_oids=("1.1",),
                table_oids=(),
                max_table_rows=1,
                timeout_seconds=1,
                cancellation=asyncio.Event(),
            )
        )


class FakeTransport:
    def __init__(self, response_value: SnmpResponse | BaseException) -> None:
        self.response = response_value
        self.calls: list[tuple[str, object, tuple[str, ...], tuple[str, ...], int, float]] = []

    async def collect(
        self,
        target: str,
        credential: object,
        *,
        scalar_oids: tuple[str, ...],
        table_oids: tuple[str, ...],
        max_table_rows: int,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> SnmpResponse:
        assert not cancellation.is_set()
        self.calls.append(
            (target, credential, scalar_oids, table_oids, max_table_rows, timeout_seconds)
        )
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


def test_snmp_collector_persists_base_and_bounded_raw_observations(tmp_path: Path) -> None:
    repository, deployment = create_repository(tmp_path)
    secret_file = tmp_path / "secrets.env"
    raw = profile({"username": "user", "auth_key": "auth-secret"})
    secret_file.write_text("SNMP_PROFILE=" + raw)
    secret_file.chmod(0o600)
    transport = FakeTransport(
        SnmpResponse(
            (
                SnmpVarBind("1.3.6.1.2.1.1.5.0", "switch-1"),
                SnmpVarBind("1.3.6.1.2.1.2.2.1.6.7", "001122aabbcc"),
                SnmpVarBind("9.9.9", "auth-secret"),
                SnmpVarBind("8.8.8", "dropped"),
                SnmpVarBind("1.3.6.1.2.1.1.1.0", "unsupported", True),
            ),
            (CollectorIssue("partial_response", "one table unavailable", True),),
        )
    )
    collector = SnmpCollector(
        repository,
        deployment,
        "v3",
        False,
        {"site": {"type": "env_file", "path": str(secret_file)}},
        transport=transport,
        max_unknown_oids=1,
        timeout_seconds=2,
        clock=lambda: NOW,
    )
    context = CollectorContext(
        "192.168.50.2", CredentialReference("site", "SNMP_PROFILE"), asyncio.Event()
    )
    result = asyncio.run(collector.collect(context))
    assert result.item_count == 3
    assert [issue.category for issue in result.issues] == [
        "partial_response",
        "unsupported_oid",
        "unknown_oid_limit",
    ]
    assert isinstance(transport.calls[0][1], SnmpV3Credential)
    values = [
        row[0]
        for row in repository.connection.execute(
            "SELECT fact_value_json FROM observations ORDER BY id"
        )
    ]
    assert all('"target":"192.168.50.2"' in value for value in values)
    assert any(REDACTED in value for value in values)
    assert all("auth-secret" not in value for value in values)
    repository.close()


def test_snmp_collector_persists_infrastructure_source_time_and_units(tmp_path: Path) -> None:
    repository, deployment = create_repository(tmp_path)
    secret_file = tmp_path / "secrets.env"
    secret_file.write_text(
        "SNMP_PROFILE=" + profile({"username": "user", "auth_key": "auth-secret"})
    )
    secret_file.chmod(0o600)
    transport = FakeTransport(SnmpResponse(fixture_varbinds("ups.json")))
    collector = SnmpCollector(
        repository,
        deployment,
        "v3",
        False,
        {"site": {"type": "env_file", "path": str(secret_file)}},
        transport=transport,
        clock=lambda: NOW,
    )
    result = asyncio.run(
        collector.collect(
            CollectorContext(
                "192.168.50.5",
                CredentialReference("site", "SNMP_PROFILE"),
                asyncio.Event(),
            )
        )
    )
    assert result.item_count == len(fixture_varbinds("ups.json"))
    rows = repository.connection.execute(
        "SELECT fact_type, fact_value_json, source, observed_at FROM observations ORDER BY id"
    ).fetchall()
    assert all(row["source"] == "snmp" and row["observed_at"] == NOW.isoformat() for row in rows)
    runtime = next(row for row in rows if row["fact_type"].endswith("runtime_remaining"))
    assert json.loads(runtime["fact_value_json"])["unit"] == "min"
    assert all("vulnerability" not in row["fact_value_json"].casefold() for row in rows)
    repository.close()


def test_snmp_collector_requires_reference_and_propagates_transport_errors(tmp_path: Path) -> None:
    repository, deployment = create_repository(tmp_path)
    collector = SnmpCollector(
        repository, deployment, "v3", False, {}, transport=FakeTransport(SnmpResponse(()))
    )
    with pytest.raises(SnmpConfigurationError, match="one approved IPv4 host"):
        asyncio.run(collector.collect(CollectorContext("192.0.2.0/24", None, asyncio.Event())))
    with pytest.raises(SnmpConfigurationError, match="credential reference"):
        asyncio.run(collector.collect(CollectorContext("192.0.2.1", None, asyncio.Event())))
    secret_file = tmp_path / "secret"
    secret_file.write_text('SNMP_PROFILE={"username":"u","auth_key":"12345678"}')
    secret_file.chmod(0o600)
    collector.providers = {"site": {"type": "env_file", "path": str(secret_file)}}
    collector.transport = FakeTransport(CollectorAuthenticationError("safe"))
    with pytest.raises(CollectorAuthenticationError):
        asyncio.run(
            collector.collect(
                CollectorContext(
                    "192.0.2.1", CredentialReference("site", "SNMP_PROFILE"), asyncio.Event()
                )
            )
        )
    repository.close()


@pytest.mark.parametrize(
    ("protocol", "allow", "rows", "unknown", "timeout", "message"),
    [
        ("v2c", False, 1, 1, 1, "explicit"),
        ("v1", False, 1, 1, 1, "protocol"),
        ("v3", False, 0, 1, 1, "bounds"),
        ("v3", False, 1, -1, 1, "bounds"),
        ("v3", False, 1, 1, 0, "bounds"),
    ],
)
def test_snmp_collector_rejects_unsafe_bounds(
    tmp_path: Path,
    protocol: str,
    allow: bool,
    rows: int,
    unknown: int,
    timeout: float,
    message: str,
) -> None:
    repository, deployment = create_repository(tmp_path)
    with pytest.raises(SnmpConfigurationError, match=message):
        SnmpCollector(
            repository,
            deployment,
            protocol,
            allow,
            {},
            max_table_rows=rows,
            max_unknown_oids=unknown,
            timeout_seconds=timeout,
        )
    repository.close()
