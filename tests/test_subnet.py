"""Read-only subnet resolver tests using synthetic kernel state."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from field_discovery.subnet import (
    KernelNetworkState,
    LinuxNetworkStateReader,
    SubnetResolutionError,
    is_excluded_interface,
    resolve_subnet,
)

FIXTURE = Path(__file__).parent / "fixtures/kernel/network-state.json"


class FixtureReader:
    def __init__(self, state: KernelNetworkState) -> None:
        self.state = state
        self.selected: str | None = None

    def read(self, interface: str) -> KernelNetworkState:
        self.selected = interface
        return self.state


def state(
    address: str = "192.168.50.25",
    prefixlen: int = 24,
    *,
    scope: str = "global",
    dynamic: bool = False,
    routes: tuple[dict[str, Any], ...] = (),
    resolv_conf: str = "",
) -> KernelNetworkState:
    entry: dict[str, Any] = {
        "family": "inet",
        "local": address,
        "prefixlen": prefixlen,
        "scope": scope,
    }
    if dynamic:
        entry["flags"] = ["dynamic"]
    return KernelNetworkState(({"addr_info": [entry]},), routes, resolv_conf)


def config(
    *,
    interface: str = "eth0",
    allow_excluded: bool = False,
    approved: list[str] | None = None,
    max_hosts: int = 256,
) -> dict[str, Any]:
    return {
        "interface": {
            "name": interface,
            "allow_excluded_interface": allow_excluded,
        },
        "active": {
            "approved_ranges": approved if approved is not None else ["192.168.50.0/24"],
            "max_hosts": max_hosts,
        },
    }


def test_kernel_fixture_normalizes_first_global_address_and_metadata() -> None:
    document = json.loads(FIXTURE.read_text())
    kernel = KernelNetworkState(
        tuple(document["addresses"]), tuple(document["routes"]), document["resolv_conf"]
    )
    reader = FixtureReader(kernel)

    result = resolve_subnet(config(), reader)

    assert reader.selected == "eth0"
    assert result.as_dict() == {
        "interface": "eth0",
        "address": "192.168.50.25",
        "cidr": "192.168.50.0/24",
        "gateway": "192.168.50.1",
        "dns_servers": ["192.168.50.1", "1.1.1.1"],
        "address_source": "dhcp",
        "route_source": "static",
        "route_metric": 100,
        "active_target_permitted": True,
        "active_target_reasons": [],
    }


def test_23_is_normalized_and_allowed_with_explicit_larger_limit() -> None:
    result = resolve_subnet(
        config(approved=["10.20.0.0/16"], max_hosts=512),
        FixtureReader(state("10.20.3.9", 23)),
    )
    assert result.cidr == "10.20.2.0/23"
    assert result.address_source == "kernel"
    assert result.gateway is None
    assert result.route_source is None
    assert result.route_metric is None
    assert result.active_target_permitted


def test_multiple_addresses_skip_non_global_and_malformed_entries() -> None:
    kernel = KernelNetworkState(
        (
            {"addr_info": "unexpected"},
            {
                "addr_info": [
                    "unexpected",
                    {"family": "inet", "scope": "link", "local": "169.254.1.2", "prefixlen": 16},
                    {"family": "inet", "scope": "global", "local": 123, "prefixlen": 24},
                    {"family": "inet", "scope": "global", "local": "broken", "prefixlen": 24},
                    {"family": "inet", "scope": "global", "local": "172.16.5.9", "prefixlen": 24},
                    {"family": "inet", "scope": "global", "local": "172.16.6.9", "prefixlen": 24},
                ]
            },
        ),
        ({"dst": "not-default"}, {"dst": "default", "gateway": "invalid", "metric": "bad"}),
        "nameserver fe80::1%eth0\nnameserver nope\n",
    )
    result = resolve_subnet(config(approved=["172.16.5.0/24"]), FixtureReader(kernel))
    assert result.address == "172.16.5.9"
    assert result.gateway is None
    assert result.dns_servers == ("fe80::1",)


def test_no_global_address_is_actionable() -> None:
    with pytest.raises(SubnetResolutionError, match="no global IPv4"):
        resolve_subnet(config(), FixtureReader(state(scope="link")))


@pytest.mark.parametrize("name", ["lo", "wlan0", "docker0", "Docker42", "tailscale0"])
def test_excluded_interface_requires_explicit_selection(name: str) -> None:
    assert is_excluded_interface(name)
    with pytest.raises(SubnetResolutionError, match="excluded"):
        resolve_subnet(config(interface=name), FixtureReader(state()))
    result = resolve_subnet(config(interface=name, allow_excluded=True), FixtureReader(state()))
    assert result.interface == name


def test_normal_interface_is_not_excluded() -> None:
    assert not is_excluded_interface("enp1s0")


def test_unsafe_broad_or_unapproved_prefix_is_described_but_refused() -> None:
    result = resolve_subnet(
        config(approved=["10.0.0.0/8"], max_hosts=256),
        FixtureReader(state("10.2.3.4", 16)),
    )
    assert result.cidr == "10.2.0.0/16"
    assert not result.active_target_permitted
    assert result.active_target_reasons == ("CIDR has 65536 addresses; maximum is 256",)

    unapproved = resolve_subnet(config(approved=[]), FixtureReader(state()))
    assert not unapproved.active_target_permitted
    assert "not within" in unapproved.active_target_reasons[0]

    malformed_approvals = config()
    malformed_approvals["active"]["approved_ranges"] = [None, "::/0"]
    malformed = resolve_subnet(malformed_approvals, FixtureReader(state()))
    assert not malformed.active_target_permitted

    not_a_list = config()
    not_a_list["active"]["approved_ranges"] = "192.168.50.0/24"
    assert not resolve_subnet(not_a_list, FixtureReader(state())).active_target_permitted


@pytest.mark.parametrize(
    ("broken", "message"),
    [
        ({}, "validated interface"),
        ({"interface": {}, "active": {}}, "interface name"),
        (
            {
                "interface": {"name": "eth0"},
                "active": {"approved_ranges": [None], "max_hosts": True},
            },
            "max_hosts",
        ),
    ],
)
def test_invalid_internal_contract_is_rejected(broken: dict[str, Any], message: str) -> None:
    with pytest.raises(SubnetResolutionError, match=message):
        resolve_subnet(broken, FixtureReader(state()))


def test_linux_reader_matches_ip_json_without_scanning(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resolver = tmp_path / "resolv.conf"
    resolver.write_text("nameserver 10.0.0.53\n")
    calls: list[list[str]] = []

    def completed(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs == {
            "check": True,
            "capture_output": True,
            "text": True,
            "timeout": 5,
        }
        output = '[{"addr_info": []}]' if "address" in command else '[{"dst": "default"}]'
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", completed)
    result = LinuxNetworkStateReader(resolver).read("eth0")
    assert result.resolv_conf == "nameserver 10.0.0.53\n"
    assert calls == [
        ["ip", "-j", "-4", "address", "show", "dev", "eth0"],
        ["ip", "-j", "-4", "route", "show", "default", "dev", "eth0"],
    ]
    assert all("nmap" not in part for call in calls for part in call)


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (FileNotFoundError(), "not installed"),
        (subprocess.TimeoutExpired("ip", 5), "timed out"),
        (subprocess.CalledProcessError(1, "ip"), "unavailable"),
    ],
)
def test_linux_reader_command_failures_are_safe(
    monkeypatch: pytest.MonkeyPatch, failure: Exception, message: str
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise failure

    monkeypatch.setattr(subprocess, "run", fail)
    with pytest.raises(SubnetResolutionError, match=message):
        LinuxNetworkStateReader().read("eth0")


@pytest.mark.parametrize("output", ["not-json", "{}", "[1]"])
def test_linux_reader_rejects_bad_json(monkeypatch: pytest.MonkeyPatch, output: str) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess("ip", 0, stdout=output, stderr=""),
    )
    with pytest.raises(SubnetResolutionError, match="JSON"):
        LinuxNetworkStateReader().read("eth0")


def test_linux_reader_reports_resolver_read_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess("ip", 0, stdout="[]", stderr=""),
    )
    with pytest.raises(SubnetResolutionError, match="resolver"):
        LinuxNetworkStateReader(tmp_path / "missing").read("eth0")
