"""Strict, non-secret CodexNet configuration contract (schema version 1)."""

from __future__ import annotations

import copy
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus, urlsplit

import yaml

MAX_CONFIG_BYTES = 1_048_576
_REFERENCE_KEY = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_INLINE_SECRET_KEYS = {
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "api-key",
    "apikey",
    "community",
    "snmp_community",
    "community_string",
    "private_key",
    "auth_key",
    "priv_key",
    "client_secret",
}
_MAX_URL_DECODE_PASSES = 2


class ConfigurationError(ValueError):
    """An actionable, secret-free configuration validation error."""


@dataclass(frozen=True)
class Configuration:
    """Validated non-secret configuration."""

    data: dict[str, Any]

    def serialized(self) -> str:
        """Return deterministic non-secret JSON for diagnostics or hashing."""
        return json.dumps(self.data, sort_keys=True, separators=(",", ":"))


_DEFAULTS: dict[str, Any] = {
    "interface": {"name": "eth0", "allow_excluded_interface": False},
    "active": {"approved_ranges": [], "max_hosts": 256},
    "paths": {"nmap_results": "/var/log/network-discovery"},
    "scheduler": {
        "interval_seconds": 3600,
        "jitter_seconds": 120,
        "timeout_seconds": 30,
        "retries": 1,
        "concurrency": 4,
    },
    "collectors": {
        "snmp": {
            "enabled": False,
            "protocol": "v3",
            "allow_insecure_v2c": False,
            "credential_ref": None,
        },
        "unifi": {"enabled": False, "endpoints": []},
        "ad": {
            "enabled": False,
            "transport": "ldaps",
            "allow_plaintext_ldap": False,
            "domain": None,
            "base_dn": None,
            "credential_ref": None,
        },
        "ssh": {
            "enabled": False,
            "host_key_policy": "strict",
            "credential_ref": None,
        },
    },
    "secret_providers": {},
    "report": {"confidentiality": "Confidential", "template": None},
    "retention": {"detailed_days": 30, "diagnostic_capture_hours": 24},
}

_ALLOWED: dict[str, set[str]] = {
    "": {
        "schema_version",
        "interface",
        "active",
        "paths",
        "scheduler",
        "collectors",
        "secret_providers",
        "report",
        "retention",
    },
    "interface": {"name", "allow_excluded_interface"},
    "active": {"approved_ranges", "max_hosts"},
    "paths": {"nmap_results"},
    "scheduler": {
        "interval_seconds",
        "jitter_seconds",
        "timeout_seconds",
        "retries",
        "concurrency",
    },
    "collectors": {"snmp", "unifi", "ad", "ssh"},
    "collectors.snmp": {"enabled", "protocol", "allow_insecure_v2c", "credential_ref"},
    "collectors.unifi": {"enabled", "endpoints"},
    "collectors.ad": {
        "enabled",
        "transport",
        "allow_plaintext_ldap",
        "domain",
        "base_dn",
        "credential_ref",
    },
    "collectors.ssh": {"enabled", "host_key_policy", "credential_ref"},
    "report": {"confidentiality", "template"},
    "retention": {"detailed_days", "diagnostic_capture_hours"},
}


def load_config(path: Path) -> Configuration:
    """Load and validate a YAML file without resolving any secret values."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigurationError(f"cannot read configuration: {path}") from exc
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigurationError(f"configuration exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ConfigurationError("configuration is not valid YAML") from exc
    return validate_config(document)


def validate_config(document: object) -> Configuration:
    """Validate parsed YAML and apply safe defaults."""
    if not isinstance(document, dict):
        raise ConfigurationError("configuration root must be a mapping")
    _reject_inline_secrets(document)
    _check_known_keys(document, "")
    if document.get("schema_version") != 1:
        raise ConfigurationError("schema_version must be integer 1")
    merged = _merge(_DEFAULTS, document)
    _validate_types(merged)
    _validate_targets(merged["active"])
    _validate_providers_and_references(merged)
    _validate_protocols(merged["collectors"])
    return Configuration(merged)


def _merge(defaults: dict[str, Any], supplied: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(defaults)
    for key, value in supplied.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _reject_inline_secrets(value: object, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if str(key).lower() in _INLINE_SECRET_KEYS:
                raise ConfigurationError(
                    f"{child_path} is an inline secret; use credential_ref with a secret provider"
                )
            _reject_inline_secrets(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_inline_secrets(child, f"{path}[{index}]")


def _check_known_keys(value: dict[Any, Any], path: str) -> None:
    if not all(isinstance(key, str) for key in value):
        raise ConfigurationError(f"{path or 'configuration'} keys must be strings")
    if path == "secret_providers":
        for name, provider in value.items():
            if not _NAME.fullmatch(name):
                raise ConfigurationError(f"secret_providers.{name} has an invalid provider name")
            _check_provider_keys(provider, f"secret_providers.{name}")
        return
    allowed = _ALLOWED.get(path)
    if allowed is None:
        return
    unknown = sorted(set(value) - allowed)
    if unknown:
        location = path or "configuration"
        raise ConfigurationError(f"{location} contains unknown key: {unknown[0]}")
    for key, child in value.items():
        child_path = f"{path}.{key}" if path else key
        if isinstance(child, dict):
            _check_known_keys(child, child_path)
        elif child_path == "collectors.unifi.endpoints" and isinstance(child, list):
            for index, endpoint in enumerate(child):
                _check_endpoint_keys(endpoint, f"{child_path}[{index}]")


def _check_provider_keys(provider: object, path: str) -> None:
    if not isinstance(provider, dict):
        raise ConfigurationError(f"{path} must be a mapping")
    provider_type = provider.get("type")
    if provider_type == "env_file":
        allowed = {"type", "path"}
    elif provider_type == "command":
        allowed = {"type", "executable", "timeout_seconds"}
    else:
        allowed = {"type", "path", "executable", "timeout_seconds"}
    unknown = sorted(set(provider) - allowed)
    if unknown:
        raise ConfigurationError(f"{path} contains unknown key: {unknown[0]}")


def _check_endpoint_keys(endpoint: object, path: str) -> None:
    if not isinstance(endpoint, dict):
        raise ConfigurationError(f"{path} must be a mapping")
    unknown = sorted(set(endpoint) - {"url", "verify_tls", "allow_self_signed", "credential_ref"})
    if unknown:
        raise ConfigurationError(f"{path} contains unknown key: {unknown[0]}")


def _integer(value: object, path: str, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ConfigurationError(f"{path} must be an integer from {minimum} to {maximum}")


def _boolean(value: object, path: str) -> None:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{path} must be true or false")


def _decoded_forms(value: str) -> list[str]:
    forms = [value]
    for _ in range(_MAX_URL_DECODE_PASSES):
        forms.append(unquote_plus(forms[-1]))
    return forms


def _contains_credential_parameter(value: str) -> bool:
    sensitive = _INLINE_SECRET_KEYS | {"client_secret"}
    for form in _decoded_forms(value):
        for field in re.split(r"[&;]", form):
            key = field.partition("=")[0].strip().casefold()
            if key in sensitive:
                return True
    return False


def _validate_types(config: dict[str, Any]) -> None:
    interface = config["interface"]
    if not isinstance(interface["name"], str) or not interface["name"]:
        raise ConfigurationError("interface.name must be a non-empty string")
    _boolean(interface["allow_excluded_interface"], "interface.allow_excluded_interface")
    excluded = interface["name"] in {"lo", "wlan0"} or interface["name"].startswith(
        ("docker", "tailscale")
    )
    if excluded and not interface["allow_excluded_interface"]:
        raise ConfigurationError(
            "interface.name is excluded by default; set allow_excluded_interface: true explicitly"
        )
    active = config["active"]
    if not isinstance(active["approved_ranges"], list):
        raise ConfigurationError("active.approved_ranges must be a list")
    _integer(active["max_hosts"], "active.max_hosts", 1, 1024)
    paths = config["paths"]
    if not isinstance(paths["nmap_results"], str) or not Path(paths["nmap_results"]).is_absolute():
        raise ConfigurationError("paths.nmap_results must be an absolute path")
    scheduler = config["scheduler"]
    _integer(scheduler["interval_seconds"], "scheduler.interval_seconds", 60, 604800)
    _integer(scheduler["jitter_seconds"], "scheduler.jitter_seconds", 0, 3600)
    _integer(scheduler["timeout_seconds"], "scheduler.timeout_seconds", 1, 300)
    _integer(scheduler["retries"], "scheduler.retries", 0, 3)
    _integer(scheduler["concurrency"], "scheduler.concurrency", 1, 16)
    if scheduler["jitter_seconds"] >= scheduler["interval_seconds"]:
        raise ConfigurationError("scheduler.jitter_seconds must be less than interval_seconds")
    for name, collector in config["collectors"].items():
        _boolean(collector["enabled"], f"collectors.{name}.enabled")
    report = config["report"]
    if not isinstance(report["confidentiality"], str) or not report["confidentiality"].strip():
        raise ConfigurationError("report.confidentiality must be a non-empty string")
    if report["template"] is not None and (
        not isinstance(report["template"], str) or not Path(report["template"]).is_absolute()
    ):
        raise ConfigurationError("report.template must be null or an absolute path")
    retention = config["retention"]
    _integer(retention["detailed_days"], "retention.detailed_days", 1, 365)
    _integer(retention["diagnostic_capture_hours"], "retention.diagnostic_capture_hours", 1, 168)


def _validate_targets(active: dict[str, Any]) -> None:
    for index, value in enumerate(active["approved_ranges"]):
        path = f"active.approved_ranges[{index}]"
        if not isinstance(value, str):
            raise ConfigurationError(f"{path} must be an IPv4 CIDR string")
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ConfigurationError(f"{path} must be a canonical IPv4 CIDR") from exc
        if network.version != 4:
            raise ConfigurationError(f"{path} must be IPv4; IPv6 is out of scope")
        if not network.is_private or network.is_loopback or network.is_link_local:
            raise ConfigurationError(
                f"{path} must be a private, non-loopback, non-link-local range"
            )
        if network.num_addresses > active["max_hosts"]:
            raise ConfigurationError(
                f"{path} has {network.num_addresses} addresses, exceeding "
                f"active.max_hosts={active['max_hosts']}"
            )


def _validate_providers_and_references(config: dict[str, Any]) -> None:
    providers = config["secret_providers"]
    for name, provider in providers.items():
        provider_type = provider.get("type")
        path = f"secret_providers.{name}"
        if provider_type == "env_file":
            value = provider.get("path")
            if not isinstance(value, str) or not Path(value).is_absolute():
                raise ConfigurationError(f"{path}.path must be an absolute restricted file path")
        elif provider_type == "command":
            executable = provider.get("executable")
            if not isinstance(executable, str) or not Path(executable).is_absolute():
                raise ConfigurationError(f"{path}.executable must be an absolute path")
            _integer(provider.get("timeout_seconds", 5), f"{path}.timeout_seconds", 1, 30)
        else:
            raise ConfigurationError(f"{path}.type must be env_file or command")
    references: list[tuple[str, object]] = []
    for collector_name in ("snmp", "ad", "ssh"):
        collector = config["collectors"][collector_name]
        references.append(
            (f"collectors.{collector_name}.credential_ref", collector["credential_ref"])
        )
    for index, endpoint in enumerate(config["collectors"]["unifi"]["endpoints"]):
        references.append(
            (f"collectors.unifi.endpoints[{index}].credential_ref", endpoint.get("credential_ref"))
        )
    for path, reference in references:
        if reference is None:
            continue
        if not isinstance(reference, dict) or set(reference) != {"provider", "key"}:
            raise ConfigurationError(f"{path} must contain exactly provider and key")
        if reference["provider"] not in providers:
            raise ConfigurationError(f"{path}.provider names an unknown secret provider")
        if not isinstance(reference["key"], str) or not _REFERENCE_KEY.fullmatch(reference["key"]):
            raise ConfigurationError(f"{path}.key must be an uppercase secret identifier")


def _validate_protocols(collectors: dict[str, Any]) -> None:
    snmp = collectors["snmp"]
    _boolean(snmp["allow_insecure_v2c"], "collectors.snmp.allow_insecure_v2c")
    if snmp["protocol"] not in {"v3", "v2c"}:
        raise ConfigurationError("collectors.snmp.protocol must be v3 or v2c")
    if snmp["protocol"] == "v2c" and not snmp["allow_insecure_v2c"]:
        raise ConfigurationError("SNMPv2c requires explicit allow_insecure_v2c: true")
    ad = collectors["ad"]
    _boolean(ad["allow_plaintext_ldap"], "collectors.ad.allow_plaintext_ldap")
    if ad["transport"] not in {"kerberos", "ldaps", "ldap"}:
        raise ConfigurationError("collectors.ad.transport must be kerberos, ldaps, or ldap")
    if ad["transport"] == "ldap" and not ad["allow_plaintext_ldap"]:
        raise ConfigurationError("plaintext LDAP requires explicit allow_plaintext_ldap: true")
    if ad["enabled"] and not all(
        isinstance(ad[field], str) and ad[field] for field in ("domain", "base_dn")
    ):
        raise ConfigurationError("enabled AD collection requires domain and base_dn")
    ssh = collectors["ssh"]
    if ssh["host_key_policy"] not in {"strict", "accept-new"}:
        raise ConfigurationError("collectors.ssh.host_key_policy must be strict or accept-new")
    for index, endpoint in enumerate(collectors["unifi"]["endpoints"]):
        path = f"collectors.unifi.endpoints[{index}]"
        url = endpoint.get("url")
        if not isinstance(url, str):
            raise ConfigurationError(f"{path}.url must use https://")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ConfigurationError(f"{path}.url must use https://")
        if any("@" in form for form in _decoded_forms(parsed.netloc)):
            raise ConfigurationError(f"{path}.url must not contain userinfo credentials")
        if _contains_credential_parameter(parsed.query):
            raise ConfigurationError(f"{path}.url must not contain credential query parameters")
        if _contains_credential_parameter(parsed.fragment):
            raise ConfigurationError(f"{path}.url must not contain credential fragments")
        _boolean(endpoint.get("verify_tls"), f"{path}.verify_tls")
        _boolean(endpoint.get("allow_self_signed"), f"{path}.allow_self_signed")
        if not endpoint["verify_tls"] and not endpoint["allow_self_signed"]:
            raise ConfigurationError(
                f"{path} disabling TLS verification requires explicit allow_self_signed: true"
            )
