"""SNMPv3-first collection, bounded OID profiles, and secure credential resolution."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from pysnmp.hlapi.v3arch.asyncio import (  # type: ignore[import-untyped]
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC128_SHA224,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC256_SHA384,
    USM_AUTH_HMAC384_SHA512,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
)

from field_discovery.collectors import (
    CollectorAuthenticationError,
    CollectorContext,
    CollectorError,
    CollectorIssue,
    CollectorResult,
    CredentialReference,
    RetryableCollectorError,
)
from field_discovery.redaction import Redactor
from field_discovery.repository import Repository

MAX_SECRET_BYTES = 65_536
MAX_VALUE_CHARS = 4_096


class SnmpConfigurationError(CollectorError):
    """SNMP configuration or credential profile is invalid."""


class SnmpProtocolError(CollectorError):
    """An SNMP agent returned an invalid or permanent protocol error."""


@dataclass(frozen=True)
class SnmpV3Credential:
    """Ephemeral USM credential material, deliberately excluded from repr."""

    username: str
    auth_key: str = field(repr=False)
    auth_protocol: str = "sha256"
    priv_key: str | None = field(default=None, repr=False)
    priv_protocol: str | None = "aes128"

    @property
    def secrets(self) -> tuple[str, ...]:
        return tuple(value for value in (self.auth_key, self.priv_key) if value)


@dataclass(frozen=True)
class SnmpV2cCredential:
    """Explicit legacy community credential, deliberately excluded from repr."""

    community: str = field(repr=False)

    @property
    def secrets(self) -> tuple[str, ...]:
        return (self.community,)


SnmpCredential = SnmpV3Credential | SnmpV2cCredential


def parse_snmp_credential(raw: str, *, protocol: str, allow_insecure_v2c: bool) -> SnmpCredential:
    """Parse one secret-provider JSON value without accepting defaults or extra fields."""
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SnmpConfigurationError("SNMP credential profile must be JSON") from exc
    if not isinstance(value, dict):
        raise SnmpConfigurationError("SNMP credential profile must be a JSON object")
    if protocol == "v2c":
        if not allow_insecure_v2c:
            raise SnmpConfigurationError("SNMPv2c requires explicit allow_insecure_v2c")
        if set(value) != {"community"}:
            raise SnmpConfigurationError("SNMPv2c profile must contain only community")
        community = value["community"]
        if not isinstance(community, str) or not community:
            raise SnmpConfigurationError("SNMPv2c community must be non-empty")
        return SnmpV2cCredential(community)
    if protocol != "v3":
        raise SnmpConfigurationError("SNMP protocol must be v3 or explicitly enabled v2c")
    allowed = {"username", "auth_key", "auth_protocol", "priv_key", "priv_protocol"}
    if not set(value) <= allowed or not {"username", "auth_key"} <= set(value):
        raise SnmpConfigurationError("SNMPv3 profile requires username and auth_key only")
    username = value["username"]
    auth_key = value["auth_key"]
    auth_protocol = value.get("auth_protocol", "sha256")
    priv_key = value.get("priv_key")
    priv_protocol = value.get("priv_protocol", "aes128" if priv_key is not None else None)
    if not isinstance(username, str) or not username:
        raise SnmpConfigurationError("SNMPv3 username must be non-empty")
    if not isinstance(auth_key, str) or len(auth_key) < 8:
        raise SnmpConfigurationError("SNMPv3 auth_key must contain at least eight characters")
    if not isinstance(auth_protocol, str) or auth_protocol not in _AUTH_PROTOCOLS:
        raise SnmpConfigurationError("SNMPv3 auth_protocol is unsupported")
    if priv_key is not None and (not isinstance(priv_key, str) or len(priv_key) < 8):
        raise SnmpConfigurationError("SNMPv3 priv_key must contain at least eight characters")
    if priv_key is None and priv_protocol is not None:
        raise SnmpConfigurationError("SNMPv3 priv_protocol requires priv_key")
    if priv_protocol is not None and (
        not isinstance(priv_protocol, str) or priv_protocol not in _PRIV_PROTOCOLS
    ):
        raise SnmpConfigurationError("SNMPv3 priv_protocol is unsupported")
    return SnmpV3Credential(username, auth_key, auth_protocol, priv_key, priv_protocol)


async def resolve_secret(
    reference: CredentialReference, providers: Mapping[str, Mapping[str, object]]
) -> str:
    """Resolve one named value without placing its key or value in process arguments."""
    provider = providers.get(reference.provider)
    if provider is None:
        raise SnmpConfigurationError("credential reference names an unknown provider")
    provider_type = provider.get("type")
    if provider_type == "env_file":
        path = provider.get("path")
        if not isinstance(path, str):
            raise SnmpConfigurationError("credential env_file path is invalid")
        return _read_env_secret(Path(path), reference.key)
    if provider_type == "command":
        executable = provider.get("executable")
        timeout = provider.get("timeout_seconds", 5)
        if not isinstance(executable, str) or not isinstance(timeout, int):
            raise SnmpConfigurationError("credential command provider is invalid")
        return await _command_secret(executable, reference.key, timeout)
    raise SnmpConfigurationError("credential provider type is unsupported")


def _read_env_secret(path: Path, key: str) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SnmpConfigurationError("credential file is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise SnmpConfigurationError("credential file must be a regular non-symlink")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise SnmpConfigurationError("credential file permissions must be 0600 or stricter")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise SnmpConfigurationError("credential file cannot be read") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) & 0o077:
            raise OSError("credential file changed during open")
        chunks: list[bytes] = []
        remaining = MAX_SECRET_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        raise SnmpConfigurationError("credential file cannot be read") from exc
    finally:
        os.close(descriptor)
    if len(raw) > MAX_SECRET_BYTES:
        raise SnmpConfigurationError("credential file exceeds size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnmpConfigurationError("credential file must be UTF-8") from exc
    found: str | None = None
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or not name:
            raise SnmpConfigurationError("credential file contains a malformed line")
        if name == key:
            if found is not None:
                raise SnmpConfigurationError("credential file contains a duplicate key")
            found = value
    if found is None or not found:
        raise SnmpConfigurationError("credential reference is missing or empty")
    return found


async def _command_secret(executable: str, key: str, timeout: int) -> str:
    process: asyncio.subprocess.Process | None = None
    try:
        process = await asyncio.create_subprocess_exec(
            executable,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
        stdout, _ = await asyncio.wait_for(
            process.communicate((key + "\n").encode()), timeout=timeout
        )
    except TimeoutError as exc:
        if process is not None:
            process.kill()
            await process.wait()
        raise SnmpConfigurationError("credential command failed") from exc
    except OSError as exc:
        raise SnmpConfigurationError("credential command failed") from exc
    if process.returncode != 0 or not stdout or len(stdout) > MAX_SECRET_BYTES:
        raise SnmpConfigurationError("credential command returned no usable value")
    try:
        value = stdout.rstrip(b"\r\n").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SnmpConfigurationError("credential command output must be UTF-8") from exc
    if not value:
        raise SnmpConfigurationError("credential command returned no usable value")
    return value


@dataclass(frozen=True)
class OidField:
    """One normalized OID scalar or table column."""

    oid: str
    fact_type: str
    table: bool = False
    value_kind: str = "text"
    unit: str | None = None
    enum_labels: tuple[tuple[int, str], ...] = ()
    special_values: tuple[tuple[str, str], ...] = ()


SYSTEM_PROFILE = (
    OidField("1.3.6.1.2.1.1.1.0", "snmp.system.description"),
    OidField("1.3.6.1.2.1.1.2.0", "snmp.system.object_id", value_kind="oid"),
    OidField("1.3.6.1.2.1.1.3.0", "snmp.system.uptime", value_kind="integer"),
    OidField("1.3.6.1.2.1.1.5.0", "snmp.system.name"),
)
INTERFACE_PROFILE = (
    OidField("1.3.6.1.2.1.2.2.1.1", "snmp.interface.index", True, "integer"),
    OidField("1.3.6.1.2.1.2.2.1.2", "snmp.interface.description", True),
    OidField("1.3.6.1.2.1.2.2.1.6", "snmp.interface.mac", True, "mac"),
    OidField("1.3.6.1.2.1.2.2.1.7", "snmp.interface.admin_state", True, "integer"),
    OidField("1.3.6.1.2.1.2.2.1.8", "snmp.interface.oper_state", True, "integer"),
)
ADDRESS_PROFILE = (
    OidField("1.3.6.1.2.1.4.20.1.1", "snmp.address.ipv4", True, "ipv4"),
    OidField("1.3.6.1.2.1.4.20.1.2", "snmp.address.interface_index", True, "integer"),
    OidField("1.3.6.1.2.1.4.20.1.3", "snmp.address.netmask", True, "ipv4"),
)
LLDP_PROFILE = (
    OidField("1.0.8802.1.1.2.1.4.1.1.5", "snmp.lldp.remote.chassis_id", True),
    OidField("1.0.8802.1.1.2.1.4.1.1.7", "snmp.lldp.remote.port_id", True),
    OidField("1.0.8802.1.1.2.1.4.1.1.9", "snmp.lldp.remote.system_name", True),
    OidField("1.0.8802.1.1.2.1.4.1.1.10", "snmp.lldp.remote.description", True),
)
BASE_OID_REGISTRY = SYSTEM_PROFILE + INTERFACE_PROFILE + ADDRESS_PROFILE + LLDP_PROFILE

BRIDGE_PROFILE = (
    OidField("1.3.6.1.2.1.17.4.3.1.1", "snmp.bridge.mac", True, "mac"),
    OidField("1.3.6.1.2.1.17.4.3.1.2", "snmp.bridge.port", True, "integer"),
    OidField(
        "1.3.6.1.2.1.17.4.3.1.3",
        "snmp.bridge.status",
        True,
        "integer",
        enum_labels=((1, "other"), (2, "invalid"), (3, "learned"), (4, "self"), (5, "management")),
    ),
)
NEIGHBOR_PROFILE = (
    OidField("1.3.6.1.2.1.4.22.1.1", "snmp.neighbor.interface_index", True, "integer"),
    OidField("1.3.6.1.2.1.4.22.1.2", "snmp.neighbor.mac", True, "mac"),
    OidField("1.3.6.1.2.1.4.22.1.3", "snmp.neighbor.ipv4", True, "ipv4"),
    OidField(
        "1.3.6.1.2.1.4.22.1.4",
        "snmp.neighbor.mapping_type",
        True,
        "integer",
        enum_labels=((1, "other"), (2, "invalid"), (3, "dynamic"), (4, "static")),
    ),
)
VLAN_PROFILE = (
    OidField("1.3.6.1.2.1.17.7.1.4.3.1.1", "snmp.vlan.name", True),
    OidField("1.3.6.1.2.1.17.7.1.4.3.1.2", "snmp.vlan.egress_ports", True, "hex_bytes"),
    OidField("1.3.6.1.2.1.17.7.1.4.3.1.3", "snmp.vlan.forbidden_ports", True, "hex_bytes"),
    OidField("1.3.6.1.2.1.17.7.1.4.3.1.4", "snmp.vlan.untagged_ports", True, "hex_bytes"),
    OidField(
        "1.3.6.1.2.1.17.7.1.4.3.1.5",
        "snmp.vlan.row_status",
        True,
        "integer",
        enum_labels=(
            (1, "active"),
            (2, "not_in_service"),
            (3, "not_ready"),
            (4, "create_and_go"),
            (5, "create_and_wait"),
            (6, "destroy"),
        ),
    ),
)
POE_PROFILE = (
    OidField(
        "1.3.6.1.2.1.105.1.1.1.3",
        "snmp.poe.port.admin_state",
        True,
        "integer",
        enum_labels=((1, "enabled"), (2, "disabled")),
    ),
    OidField(
        "1.3.6.1.2.1.105.1.1.1.6",
        "snmp.poe.port.detection_status",
        True,
        "integer",
        enum_labels=(
            (1, "disabled"),
            (2, "searching"),
            (3, "delivering_power"),
            (4, "fault"),
            (5, "test"),
            (6, "other_fault"),
        ),
    ),
    OidField(
        "1.3.6.1.2.1.105.1.1.1.7",
        "snmp.poe.port.priority",
        True,
        "integer",
        enum_labels=((1, "critical"), (2, "high"), (3, "low")),
    ),
    OidField("1.3.6.1.2.1.105.1.1.1.13", "snmp.poe.port.class", True, "integer"),
    OidField("1.3.6.1.2.1.105.1.3.1.1.2", "snmp.poe.main.power_budget", True, "integer", "W"),
    OidField("1.3.6.1.2.1.105.1.3.1.1.4", "snmp.poe.main.power_consumption", True, "integer", "W"),
)
ENVIRONMENT_PROFILE = (
    OidField(
        "1.3.6.1.2.1.99.1.1.1.1",
        "snmp.environment.sensor.type",
        True,
        "integer",
        enum_labels=(
            (1, "other"),
            (2, "unknown"),
            (3, "volts_ac"),
            (4, "volts_dc"),
            (5, "amperes"),
            (6, "watts"),
            (7, "hertz"),
            (8, "celsius"),
            (9, "percent_relative_humidity"),
            (10, "rpm"),
        ),
    ),
    OidField(
        "1.3.6.1.2.1.99.1.1.1.2",
        "snmp.environment.sensor.scale",
        True,
        "integer",
        enum_labels=(
            (1, "yocto"),
            (2, "zepto"),
            (3, "atto"),
            (4, "femto"),
            (5, "pico"),
            (6, "nano"),
            (7, "micro"),
            (8, "milli"),
            (9, "units"),
            (10, "kilo"),
            (11, "mega"),
            (12, "giga"),
            (13, "tera"),
            (14, "exa"),
            (15, "peta"),
            (16, "zetta"),
            (17, "yotta"),
        ),
    ),
    OidField(
        "1.3.6.1.2.1.99.1.1.1.3",
        "snmp.environment.sensor.precision",
        True,
        "integer",
        "decimal_places",
    ),
    OidField("1.3.6.1.2.1.99.1.1.1.4", "snmp.environment.sensor.value", True, "integer"),
    OidField(
        "1.3.6.1.2.1.99.1.1.1.5",
        "snmp.environment.sensor.oper_state",
        True,
        "integer",
        enum_labels=((1, "ok"), (2, "unavailable"), (3, "nonoperational")),
    ),
    OidField("1.3.6.1.2.1.99.1.1.1.6", "snmp.environment.sensor.units_display", True),
    OidField(
        "1.3.6.1.2.1.99.1.1.1.7",
        "snmp.environment.sensor.timestamp",
        True,
        "integer",
        "centiseconds",
    ),
)
UPS_PROFILE = (
    OidField(
        "1.3.6.1.2.1.33.1.2.1.0",
        "snmp.ups.battery.status",
        enum_labels=((1, "unknown"), (2, "normal"), (3, "low"), (4, "depleted")),
        value_kind="integer",
    ),
    OidField(
        "1.3.6.1.2.1.33.1.2.2.0",
        "snmp.ups.battery.seconds_on_battery",
        value_kind="integer",
        unit="s",
    ),
    OidField(
        "1.3.6.1.2.1.33.1.2.3.0",
        "snmp.ups.battery.runtime_remaining",
        value_kind="integer",
        unit="min",
    ),
    OidField(
        "1.3.6.1.2.1.33.1.2.4.0",
        "snmp.ups.battery.charge_remaining",
        value_kind="integer",
        unit="%",
    ),
    OidField(
        "1.3.6.1.2.1.33.1.2.5.0", "snmp.ups.battery.voltage", value_kind="integer", unit="0.1 V DC"
    ),
    OidField(
        "1.3.6.1.2.1.33.1.2.6.0", "snmp.ups.battery.current", value_kind="integer", unit="0.1 A DC"
    ),
    OidField(
        "1.3.6.1.2.1.33.1.2.7.0", "snmp.ups.battery.temperature", value_kind="integer", unit="°C"
    ),
)
PRINTER_PROFILE = (
    OidField("1.3.6.1.2.1.43.5.1.1.17", "snmp.printer.serial", True),
    OidField(
        "1.3.6.1.2.1.43.10.2.1.3",
        "snmp.printer.marker.counter_unit",
        True,
        "integer",
        enum_labels=(
            (1, "other"),
            (2, "unknown"),
            (5, "characters"),
            (6, "lines"),
            (7, "impressions"),
            (8, "sheets"),
            (11, "hours"),
        ),
    ),
    OidField("1.3.6.1.2.1.43.10.2.1.4", "snmp.printer.marker.life_count", True, "integer"),
    OidField("1.3.6.1.2.1.43.11.1.1.4", "snmp.printer.supply.class", True, "integer"),
    OidField("1.3.6.1.2.1.43.11.1.1.5", "snmp.printer.supply.type", True, "integer"),
    OidField("1.3.6.1.2.1.43.11.1.1.6", "snmp.printer.supply.description", True),
    OidField(
        "1.3.6.1.2.1.43.11.1.1.7",
        "snmp.printer.supply.unit",
        True,
        "integer",
        enum_labels=(
            (1, "other"),
            (2, "unknown"),
            (16, "feet"),
            (17, "meters"),
            (18, "items"),
            (19, "percent"),
        ),
    ),
    OidField(
        "1.3.6.1.2.1.43.11.1.1.8",
        "snmp.printer.supply.maximum_capacity",
        True,
        "integer",
        special_values=(("-1", "other"), ("-2", "unknown")),
    ),
    OidField(
        "1.3.6.1.2.1.43.11.1.1.9",
        "snmp.printer.supply.level",
        True,
        "integer",
        special_values=(("-1", "other"), ("-2", "unknown"), ("-3", "some_remaining")),
    ),
)
FIRMWARE_PROFILE = (
    OidField("1.3.6.1.2.1.47.1.1.1.1.9", "snmp.firmware.revision", True),
    OidField("1.3.6.1.2.1.47.1.1.1.1.10", "snmp.software.revision", True),
    OidField("1.3.6.1.2.1.47.1.1.1.1.11", "snmp.inventory.serial", True),
    OidField("1.3.6.1.2.1.47.1.1.1.1.13", "snmp.inventory.model", True),
)
INFRASTRUCTURE_OID_REGISTRY = (
    BRIDGE_PROFILE
    + NEIGHBOR_PROFILE
    + VLAN_PROFILE
    + POE_PROFILE
    + ENVIRONMENT_PROFILE
    + UPS_PROFILE
    + PRINTER_PROFILE
    + FIRMWARE_PROFILE
)
DEFAULT_OID_REGISTRY = BASE_OID_REGISTRY + INFRASTRUCTURE_OID_REGISTRY


@dataclass(frozen=True)
class SnmpVarBind:
    oid: str
    value: object
    unsupported: bool = False


@dataclass(frozen=True)
class SnmpResponse:
    varbinds: tuple[SnmpVarBind, ...]
    issues: tuple[CollectorIssue, ...] = ()
    truncated: bool = False


class SnmpTransport(Protocol):
    async def collect(
        self,
        target: str,
        credential: SnmpCredential,
        *,
        scalar_oids: Sequence[str],
        table_oids: Sequence[str],
        max_table_rows: int,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> SnmpResponse: ...


_AUTH_PROTOCOLS: dict[str, Any] = {
    "sha1": USM_AUTH_HMAC96_SHA,
    "sha224": USM_AUTH_HMAC128_SHA224,
    "sha256": USM_AUTH_HMAC192_SHA256,
    "sha384": USM_AUTH_HMAC256_SHA384,
    "sha512": USM_AUTH_HMAC384_SHA512,
}
_PRIV_PROTOCOLS: dict[str, Any] = {
    "aes128": USM_PRIV_CFB128_AES,
    "aes192": USM_PRIV_CFB192_AES,
    "aes256": USM_PRIV_CFB256_AES,
}


class PySnmpTransport:
    """Async UDP transport using PySNMP with one engine per isolated run."""

    async def collect(
        self,
        target: str,
        credential: SnmpCredential,
        *,
        scalar_oids: Sequence[str],
        table_oids: Sequence[str],
        max_table_rows: int,
        timeout_seconds: float,
        cancellation: asyncio.Event,
    ) -> SnmpResponse:
        engine = SnmpEngine()
        auth = _pysnmp_auth(credential)
        transport = await UdpTransportTarget.create(
            (target, 161), timeout=timeout_seconds, retries=0
        )
        context = ContextData()
        values: list[SnmpVarBind] = []
        issues: list[CollectorIssue] = []
        truncated = False
        try:
            if scalar_oids:
                response = await get_cmd(
                    engine,
                    auth,
                    transport,
                    context,
                    *(ObjectType(ObjectIdentity(oid)) for oid in scalar_oids),
                    lookupMib=False,
                )
                values.extend(_response_varbinds(response))
            remaining = max_table_rows
            for root in table_oids:
                if cancellation.is_set():
                    raise asyncio.CancelledError
                if remaining == 0:
                    truncated = True
                    break
                async for response in bulk_walk_cmd(
                    engine,
                    auth,
                    transport,
                    context,
                    0,
                    min(25, remaining),
                    ObjectType(ObjectIdentity(root)),
                    lexicographicMode=False,
                    lookupMib=False,
                ):
                    batch = _response_varbinds(response)
                    if len(batch) > remaining:
                        batch = batch[:remaining]
                        truncated = True
                    values.extend(batch)
                    remaining -= len(batch)
                    if remaining == 0:
                        truncated = True
                        break
                if truncated:
                    break
        except (CollectorError, asyncio.CancelledError):
            raise
        except Exception as exc:
            raise RetryableCollectorError("SNMP transport failed") from exc
        finally:
            if engine.transport_dispatcher is not None:
                engine.transport_dispatcher.close_dispatcher()
        if truncated:
            issues.append(CollectorIssue("table_limit", "SNMP table row limit reached"))
        return SnmpResponse(tuple(values), tuple(issues), truncated)


def _pysnmp_auth(credential: SnmpCredential) -> CommunityData | UsmUserData:
    if isinstance(credential, SnmpV2cCredential):
        return CommunityData("codexnet-explicit-v2c", credential.community, mpModel=1)
    return UsmUserData(
        credential.username,
        credential.auth_key,
        credential.priv_key,
        authProtocol=_AUTH_PROTOCOLS[credential.auth_protocol],
        privProtocol=(
            _PRIV_PROTOCOLS[credential.priv_protocol]
            if credential.priv_protocol is not None
            else None
        ),
    )


def _response_varbinds(response: tuple[Any, Any, Any, Sequence[Any]]) -> list[SnmpVarBind]:
    error_indication, error_status, _error_index, varbinds = response
    if error_indication:
        text = str(error_indication).casefold()
        if any(token in text for token in ("authentication", "unknown user", "wrong digest")):
            raise CollectorAuthenticationError("SNMP authentication failed")
        raise RetryableCollectorError("SNMP target did not respond")
    if error_status:
        text = str(error_status)
        if "authorization" in text.casefold() or "access" in text.casefold():
            raise CollectorAuthenticationError("SNMP authorization failed")
        raise SnmpProtocolError("SNMP agent returned an error status")
    output: list[SnmpVarBind] = []
    for varbind in varbinds:
        oid, value = varbind
        class_name = value.__class__.__name__.casefold()
        output.append(
            SnmpVarBind(
                str(oid),
                value.prettyPrint(),
                any(name in class_name for name in ("nosuch", "endofmib")),
            )
        )
    return output


@dataclass
class SnmpCollector:
    """Normalize bounded base profiles into provenance-aware repository observations."""

    repository: Repository
    deployment_id: int
    protocol: str
    allow_insecure_v2c: bool
    providers: Mapping[str, Mapping[str, object]]
    transport: SnmpTransport = field(default_factory=PySnmpTransport)
    registry: Sequence[OidField] = DEFAULT_OID_REGISTRY
    max_table_rows: int = 4_096
    max_unknown_oids: int = 128
    timeout_seconds: float = 5
    clock: Any = lambda: datetime.now(UTC)
    name: str = "snmp"

    def __post_init__(self) -> None:
        if self.protocol == "v2c" and not self.allow_insecure_v2c:
            raise SnmpConfigurationError("SNMPv2c requires explicit allow_insecure_v2c")
        if self.protocol not in {"v3", "v2c"}:
            raise SnmpConfigurationError("SNMP protocol must be v3 or v2c")
        if self.max_table_rows < 1 or self.max_unknown_oids < 0 or self.timeout_seconds <= 0:
            raise SnmpConfigurationError("SNMP collection bounds are invalid")

    async def collect(self, context: CollectorContext) -> CollectorResult:
        try:
            ipaddress.IPv4Address(context.target)
        except ValueError as exc:
            raise SnmpConfigurationError("SNMP collection requires one approved IPv4 host") from exc
        if context.credential_ref is None:
            raise SnmpConfigurationError("SNMP collector requires a credential reference")
        raw = await resolve_secret(context.credential_ref, self.providers)
        credential = parse_snmp_credential(
            raw, protocol=self.protocol, allow_insecure_v2c=self.allow_insecure_v2c
        )
        redactor = Redactor(credential.secrets)
        scalar_oids = tuple(field.oid for field in self.registry if not field.table)
        table_oids = tuple(field.oid for field in self.registry if field.table)
        response = await self.transport.collect(
            context.target,
            credential,
            scalar_oids=scalar_oids,
            table_oids=table_oids,
            max_table_rows=self.max_table_rows,
            timeout_seconds=self.timeout_seconds,
            cancellation=context.cancellation,
        )
        facts, issues = normalize_varbinds(
            response.varbinds,
            self.registry,
            max_unknown=self.max_unknown_oids,
            redactor=redactor,
        )
        observed_at = self.clock().isoformat()
        for fact_type, value in facts:
            self.repository.record_observation(
                self.deployment_id,
                subject_type="snmp_target",
                subject_id=None,
                fact_type=fact_type,
                fact_value={"target": context.target, **value},
                confidence=1.0,
                inferred=False,
                source="snmp",
                observed_at=observed_at,
            )
        return CollectorResult(len(facts), response.issues + issues)


def normalize_varbinds(
    varbinds: Sequence[SnmpVarBind],
    registry: Sequence[OidField],
    *,
    max_unknown: int,
    redactor: Redactor | None = None,
) -> tuple[tuple[tuple[str, dict[str, object]], ...], tuple[CollectorIssue, ...]]:
    """Normalize known OIDs and retain only a bounded, redacted unknown set."""
    scrubber = redactor or Redactor()
    ordered = sorted(registry, key=lambda field: len(field.oid), reverse=True)
    facts: list[tuple[str, dict[str, object]]] = []
    issues: list[CollectorIssue] = []
    unknown = 0
    for varbind in varbinds:
        if varbind.unsupported:
            issues.append(CollectorIssue("unsupported_oid", f"OID {varbind.oid} is unsupported"))
            continue
        matched = next(
            (
                field
                for field in ordered
                if varbind.oid == field.oid
                or (field.table and varbind.oid.startswith(field.oid + "."))
            ),
            None,
        )
        if matched is None:
            if unknown < max_unknown:
                facts.append(
                    (
                        "snmp.raw.unknown",
                        {
                            "oid": varbind.oid,
                            "value": scrubber.text(varbind.value)[:MAX_VALUE_CHARS],
                        },
                    )
                )
                unknown += 1
            continue
        index = varbind.oid[len(matched.oid) :].lstrip(".") if matched.table else ""
        text_value = scrubber.text(varbind.value)[:MAX_VALUE_CHARS]
        special = dict(matched.special_values).get(text_value)
        if special is not None:
            payload: dict[str, object] = {
                "index": index,
                "value": None,
                "value_status": special,
                "raw_value": text_value,
            }
        else:
            try:
                value = _normalize_value(text_value, matched.value_kind, scrubber)
            except (TypeError, ValueError):
                issues.append(
                    CollectorIssue("invalid_value", f"OID {varbind.oid} value was invalid")
                )
                continue
            payload = {"index": index, "value": value}
            label = dict(matched.enum_labels).get(value) if isinstance(value, int) else None
            if label is not None:
                payload["label"] = label
        if matched.unit is not None:
            payload["unit"] = matched.unit
        facts.append((matched.fact_type, payload))
    if (
        sum(
            1
            for varbind in varbinds
            if not any(
                varbind.oid == field.oid
                or (field.table and varbind.oid.startswith(field.oid + "."))
                for field in registry
            )
        )
        > max_unknown
    ):
        issues.append(CollectorIssue("unknown_oid_limit", "unknown OID retention limit reached"))
    return tuple(facts), tuple(issues)


def _normalize_value(value: object, kind: str, redactor: Redactor) -> object:
    text = redactor.text(value)[:MAX_VALUE_CHARS]
    if kind == "integer":
        return int(text)
    if kind == "ipv4":
        return str(ipaddress.IPv4Address(text))
    if kind == "mac":
        text = text.casefold().removeprefix("0x")
        compact = "".join(character for character in text if character in "0123456789abcdef")
        if len(compact) != 12:
            raise ValueError("invalid MAC")
        return ":".join(compact[index : index + 2] for index in range(0, 12, 2))
    if kind == "hex_bytes":
        compact = text.casefold().removeprefix("0x")
        compact = "".join(compact.split()).replace(":", "").replace("-", "")
        if (
            not compact
            or len(compact) % 2
            or any(character not in "0123456789abcdef" for character in compact)
        ):
            raise ValueError("invalid byte string")
        return compact
    if kind == "oid":
        if not all(part.isdigit() for part in text.strip(".").split(".")):
            raise ValueError("invalid OID")
        return text.strip(".")
    if kind != "text":
        raise ValueError("unsupported normalization kind")
    return text
