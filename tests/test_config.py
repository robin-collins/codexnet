from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from field_discovery.config import ConfigurationError, load_config, validate_config

ROOT = Path(__file__).parents[1]


def example() -> dict[str, Any]:
    value = yaml.safe_load((ROOT / "config/example.yaml").read_text())
    assert isinstance(value, dict)
    return value


def set_path(document: dict[str, Any], path: str, value: object) -> dict[str, Any]:
    result = copy.deepcopy(document)
    parts = path.split(".")
    target: Any = result
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    if isinstance(target, list):
        target[int(parts[-1])] = value
    else:
        target[parts[-1]] = value
    return result


def test_example_loads_and_serializes_deterministically() -> None:
    config = load_config(ROOT / "config/example.yaml")
    serialized = config.serialized()
    assert json.loads(serialized)["schema_version"] == 1
    assert serialized == config.serialized()
    assert config.data["scheduler"]["interval_seconds"] == 3600


def test_minimal_configuration_gets_deny_by_default_values() -> None:
    config = validate_config({"schema_version": 1})
    assert config.data["active"]["approved_ranges"] == []
    assert not any(item["enabled"] for item in config.data["collectors"].values())
    assert config.data["collectors"]["snmp"]["protocol"] == "v3"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (None, "root must be a mapping"),
        ({"schema_version": 2}, "schema_version"),
        ({"schema_version": 1, "mystery": True}, "unknown key: mystery"),
        ({"schema_version": 1, 2: True}, "keys must be strings"),
        ({"schema_version": 1, "password": "synthetic-value"}, "inline secret"),
        ({"schema_version": 1, "nested": [{"token": "synthetic-value"}]}, "inline secret"),
    ],
)
def test_root_contract_failures(document: object, message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        validate_config(document)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        ("interface.name", "", "non-empty string"),
        ("interface.allow_excluded_interface", "yes", "true or false"),
        ("interface.name", "lo", "excluded by default"),
        ("active.approved_ranges", "192.168.1.0/24", "must be a list"),
        ("active.max_hosts", True, "integer from 1 to 1024"),
        ("paths.nmap_results", "relative", "absolute path"),
        ("paths.data_root", "relative", "absolute path"),
        ("paths.database", "relative", "absolute path"),
        ("scheduler.interval_seconds", 59, "integer from 60"),
        ("scheduler.jitter_seconds", 3600, "less than interval_seconds"),
        ("scheduler.timeout_seconds", 0, "integer from 1"),
        ("scheduler.retries", 4, "integer from 0"),
        ("scheduler.concurrency", 17, "integer from 1"),
        ("collectors.snmp.enabled", "yes", "true or false"),
        ("report.confidentiality", "", "non-empty string"),
        ("report.template", "relative.docx", "absolute path"),
        ("retention.detailed_days", 0, "integer from 1"),
        ("retention.diagnostic_capture_hours", 169, "integer from 1"),
    ],
)
def test_type_and_bound_failures(path: str, value: object, message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        validate_config(set_path(example(), path, value))


def test_explicit_excluded_interface_and_null_report_template_are_allowed() -> None:
    document = set_path(example(), "interface.name", "wlan0")
    document = set_path(document, "interface.allow_excluded_interface", True)
    document = set_path(document, "report.template", None)
    assert validate_config(document).data["interface"]["name"] == "wlan0"


@pytest.mark.parametrize(
    ("data_root", "database", "message"),
    [
        ("/var/lib/field-discovery", "/tmp/outside.db", "must be inside"),
        ("/var/lib/field-discovery", "/var/lib/field-discovery", "must be inside"),
        ("/var/lib/field-discovery/../escape", "/var/lib/escape/db", "parent traversal"),
        ("/var/lib/field-discovery", "/var/lib/field-discovery/../escape.db", "parent traversal"),
    ],
)
def test_database_paths_are_lexically_confined(data_root: str, database: str, message: str) -> None:
    document = set_path(example(), "paths.data_root", data_root)
    document = set_path(document, "paths.database", database)
    with pytest.raises(ConfigurationError, match=message):
        validate_config(document)


@pytest.mark.parametrize(
    ("ranges", "max_hosts", "message"),
    [
        ([123], 256, "IPv4 CIDR string"),
        (["192.168.1.2/24"], 256, "canonical IPv4 CIDR"),
        (["fd00::/120"], 256, "must be IPv4"),
        (["8.8.8.0/24"], 256, "must be a private"),
        (["127.0.0.0/24"], 256, "must be a private"),
        (["169.254.1.0/24"], 256, "must be a private"),
        (["10.0.0.0/23"], 256, "exceeding active.max_hosts"),
    ],
)
def test_unsafe_targets_fail(ranges: object, max_hosts: int, message: str) -> None:
    document = set_path(example(), "active.approved_ranges", ranges)
    document = set_path(document, "active.max_hosts", max_hosts)
    with pytest.raises(ConfigurationError, match=message):
        validate_config(document)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        ("collectors.snmp.protocol", "v1", "must be v3 or v2c"),
        ("collectors.snmp.allow_insecure_v2c", "yes", "true or false"),
        ("collectors.ad.transport", "ntlm", "must be kerberos"),
        ("collectors.ad.allow_plaintext_ldap", "yes", "true or false"),
        ("collectors.ssh.host_key_policy", "ignore", "strict or accept-new"),
        ("collectors.unifi.endpoints.0.url", None, "must use https"),
        ("collectors.unifi.endpoints.0.url", "http://controller.invalid", "must use https"),
        ("collectors.unifi.endpoints.0.verify_tls", "yes", "true or false"),
        ("collectors.unifi.endpoints.0.allow_self_signed", "yes", "true or false"),
    ],
)
def test_insecure_or_invalid_protocols_fail(path: str, value: object, message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        validate_config(set_path(example(), path, value))


def test_insecure_protocols_require_explicit_scoped_opt_in() -> None:
    snmp = set_path(example(), "collectors.snmp.protocol", "v2c")
    with pytest.raises(ConfigurationError, match="explicit allow_insecure_v2c"):
        validate_config(snmp)
    assert validate_config(set_path(snmp, "collectors.snmp.allow_insecure_v2c", True))

    ldap = set_path(example(), "collectors.ad.transport", "ldap")
    with pytest.raises(ConfigurationError, match="explicit allow_plaintext_ldap"):
        validate_config(ldap)
    assert validate_config(set_path(ldap, "collectors.ad.allow_plaintext_ldap", True))

    tls = set_path(example(), "collectors.unifi.endpoints.0.verify_tls", False)
    with pytest.raises(ConfigurationError, match="explicit allow_self_signed"):
        validate_config(tls)
    assert validate_config(set_path(tls, "collectors.unifi.endpoints.0.allow_self_signed", True))


@pytest.mark.parametrize(
    "url",
    [
        "https://user:synthetic@example.invalid",
        "https://:synthetic@example.invalid",
        "https://example.invalid/?access_token=synthetic",
        "https://example.invalid/?access%5Ftoken=synthetic",
        "https://example.invalid/?client_secret=synthetic",
        "https://example.invalid/?api-key=synthetic",
        "https://example.invalid/?apikey=synthetic",
        "https://example.invalid/?refresh_token=synthetic",
        "https://example.invalid/?safe=1;id_token=synthetic",
        "https://example.invalid/?%2561ccess_token=synthetic",
        "https://example.invalid/#snmp_community=synthetic",
        "https://example.invalid/#community%255Fstring=synthetic",
        "https://user%40example.invalid",
    ],
)
def test_controller_urls_reject_embedded_credentials(url: str) -> None:
    document = set_path(example(), "collectors.unifi.endpoints.0.url", url)
    with pytest.raises(ConfigurationError, match="must not contain") as caught:
        validate_config(document)
    assert "synthetic" not in str(caught.value)


def test_controller_url_allows_safe_lookalike_query_and_serializes_it() -> None:
    url = "https://example.invalid/?token_count=4&authorization_status=ok#community_name=public"
    document = set_path(example(), "collectors.unifi.endpoints.0.url", url)
    assert url in validate_config(document).serialized()


def test_controller_url_decoding_is_capped_at_two_passes() -> None:
    url = "https://example.invalid/?%252561ccess_token=synthetic"
    assert (
        url
        in validate_config(
            set_path(example(), "collectors.unifi.endpoints.0.url", url)
        ).serialized()
    )


def test_enabled_ad_requires_approved_domain_and_base_dn() -> None:
    document = set_path(example(), "collectors.ad.enabled", True)
    document = set_path(document, "collectors.ad.domain", None)
    with pytest.raises(ConfigurationError, match="requires domain and base_dn"):
        validate_config(document)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda d: d["secret_providers"].update(
                {"Bad Name": {"type": "env_file", "path": "/x"}}
            ),
            "invalid provider name",
        ),
        (lambda d: d["secret_providers"].update({"bad": "value"}), "must be a mapping"),
        (
            lambda d: d["secret_providers"]["appliance_env"].update({"extra": 1}),
            "unknown key: extra",
        ),
        (
            lambda d: d["secret_providers"]["appliance_env"].update({"type": "unknown"}),
            "type must be env_file or command",
        ),
        (
            lambda d: d["secret_providers"]["appliance_env"].update({"path": "relative"}),
            "absolute restricted file",
        ),
        (
            lambda d: d["secret_providers"]["secret_helper"].update({"executable": "relative"}),
            "executable must be an absolute",
        ),
        (
            lambda d: d["secret_providers"]["secret_helper"].update({"timeout_seconds": 31}),
            "integer from 1 to 30",
        ),
        (
            lambda d: d["collectors"]["snmp"].update({"credential_ref": "inline"}),
            "exactly provider and key",
        ),
        (
            lambda d: d["collectors"]["snmp"].update(
                {"credential_ref": {"provider": "missing", "key": "SNMP_SITE_PROFILE"}}
            ),
            "unknown secret provider",
        ),
        (
            lambda d: d["collectors"]["snmp"].update(
                {"credential_ref": {"provider": "appliance_env", "key": "bad"}}
            ),
            "uppercase secret identifier",
        ),
        (lambda d: d["collectors"]["unifi"].update({"endpoints": ["bad"]}), "must be a mapping"),
        (
            lambda d: d["collectors"]["unifi"]["endpoints"][0].update({"extra": True}),
            "unknown key: extra",
        ),
    ],
)
def test_provider_and_reference_failures(mutate: Any, message: str) -> None:
    document = example()
    mutate(document)
    with pytest.raises(ConfigurationError, match=message):
        validate_config(document)


def test_unknown_nested_key_fails() -> None:
    document = example()
    document["scheduler"]["minutes"] = 5
    with pytest.raises(ConfigurationError, match="scheduler contains unknown key: minutes"):
        validate_config(document)


def test_load_errors_are_bounded_and_do_not_echo_content(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"
    with pytest.raises(ConfigurationError, match="cannot read configuration"):
        load_config(missing)
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("schema_version: [")
    with pytest.raises(ConfigurationError, match="not valid YAML"):
        load_config(invalid)
    oversized = tmp_path / "large.yaml"
    oversized.write_bytes(b"x" * 1_048_577)
    with pytest.raises(ConfigurationError, match="exceeds 1048576 bytes"):
        load_config(oversized)
