"""Read-only interface and IPv4 subnet resolution.

This module describes kernel network state.  It does not open sockets, transmit
packets, change routes, or invoke a scanner.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol

EXCLUDED_INTERFACE_NAMES = frozenset({"lo", "wlan0"})
EXCLUDED_INTERFACE_PREFIXES = ("docker", "tailscale")
COMMAND_TIMEOUT_SECONDS = 5


class SubnetResolutionError(RuntimeError):
    """Kernel state could not provide one usable global IPv4 address."""


def is_excluded_interface(name: str) -> bool:
    """Return whether an interface is excluded unless explicitly selected."""
    lowered = name.casefold()
    return lowered in EXCLUDED_INTERFACE_NAMES or lowered.startswith(EXCLUDED_INTERFACE_PREFIXES)


@dataclass(frozen=True)
class KernelNetworkState:
    """Serializable input boundary, also used by synthetic kernel fixtures."""

    addresses: tuple[Mapping[str, Any], ...]
    routes: tuple[Mapping[str, Any], ...]
    resolv_conf: str


class NetworkStateReader(Protocol):
    """Read-only source of network state for one selected interface."""

    def read(self, interface: str) -> KernelNetworkState: ...  # pragma: no cover


class LinuxNetworkStateReader:
    """Read Linux address/route JSON and resolver configuration without mutation."""

    def __init__(self, resolv_conf: Path = Path("/etc/resolv.conf")) -> None:
        self._resolv_conf = resolv_conf

    @staticmethod
    def _ip_json(arguments: Sequence[str]) -> tuple[Mapping[str, Any], ...]:
        try:
            completed = subprocess.run(
                ["ip", "-j", "-4", *arguments],
                check=True,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except FileNotFoundError as exc:
            raise SubnetResolutionError("the ip command is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise SubnetResolutionError("timed out while reading kernel network state") from exc
        except subprocess.CalledProcessError as exc:
            raise SubnetResolutionError("the selected interface is unavailable") from exc
        try:
            value = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise SubnetResolutionError("the ip command returned invalid JSON") from exc
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise SubnetResolutionError("the ip command returned an unexpected JSON shape")
        return tuple(value)

    def read(self, interface: str) -> KernelNetworkState:
        """Read only the explicitly selected interface and its default route."""
        addresses = self._ip_json(("address", "show", "dev", interface))
        routes = self._ip_json(("route", "show", "default", "dev", interface))
        try:
            resolver = self._resolv_conf.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise SubnetResolutionError("cannot read resolver configuration") from exc
        return KernelNetworkState(addresses, routes, resolver)


@dataclass(frozen=True)
class SubnetDescription:
    """Normalized interface state and a separately evaluated active-target decision."""

    interface: str
    address: str
    cidr: str
    gateway: str | None
    dns_servers: tuple[str, ...]
    address_source: str
    route_source: str | None
    route_metric: int | None
    active_target_permitted: bool
    active_target_reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible deterministic representation."""
        value = asdict(self)
        value["dns_servers"] = list(self.dns_servers)
        value["active_target_reasons"] = list(self.active_target_reasons)
        return value


def _global_ipv4(state: KernelNetworkState) -> Mapping[str, Any]:
    for link in state.addresses:
        entries = link.get("addr_info", ())
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("family") != "inet" or entry.get("scope") != "global":
                continue
            local = entry.get("local")
            prefixlen = entry.get("prefixlen")
            if not isinstance(local, str) or not isinstance(prefixlen, int):
                continue
            try:
                ipaddress.IPv4Interface(f"{local}/{prefixlen}")
            except ValueError:
                continue
            return entry
    raise SubnetResolutionError("selected interface has no global IPv4 address")


def _default_route(state: KernelNetworkState) -> Mapping[str, Any] | None:
    routes = [route for route in state.routes if route.get("dst", "default") == "default"]
    if not routes:
        return None

    def metric(route: Mapping[str, Any]) -> int:
        value = route.get("metric", 0)
        return value if isinstance(value, int) else 0

    return min(routes, key=metric)


def _dns_servers(contents: str) -> tuple[str, ...]:
    servers: list[str] = []
    for raw_line in contents.splitlines():
        line = raw_line.partition("#")[0].strip()
        fields = line.split()
        if len(fields) < 2 or fields[0].casefold() != "nameserver":
            continue
        try:
            server = str(ipaddress.ip_address(fields[1].split("%", 1)[0]))
        except ValueError:
            continue
        if server not in servers:
            servers.append(server)
    return tuple(servers)


def _active_target_decision(
    network: ipaddress.IPv4Network, approved_values: object, max_hosts: object
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if not isinstance(max_hosts, int) or isinstance(max_hosts, bool):
        raise SubnetResolutionError("active.max_hosts is invalid")
    if network.num_addresses > max_hosts:
        reasons.append(f"CIDR has {network.num_addresses} addresses; maximum is {max_hosts}")
    approved: list[ipaddress.IPv4Network] = []
    if isinstance(approved_values, list):
        for value in approved_values:
            try:
                parsed = ipaddress.ip_network(value, strict=True)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, ipaddress.IPv4Network):
                approved.append(parsed)
    if not any(network.subnet_of(candidate) for candidate in approved):
        reasons.append("CIDR is not within an explicitly approved active range")
    return not reasons, tuple(reasons)


def resolve_subnet(
    config: Mapping[str, Any], reader: NetworkStateReader | None = None
) -> SubnetDescription:
    """Describe the configured interface and evaluate—but never use—an active target."""
    interface_config = config.get("interface")
    active_config = config.get("active")
    if not isinstance(interface_config, Mapping) or not isinstance(active_config, Mapping):
        raise SubnetResolutionError("validated interface and active configuration is required")
    interface = interface_config.get("name")
    explicitly_allowed = interface_config.get("allow_excluded_interface", False)
    if not isinstance(interface, str) or not interface:
        raise SubnetResolutionError("configured interface name is invalid")
    if is_excluded_interface(interface) and explicitly_allowed is not True:
        raise SubnetResolutionError("selected interface is excluded by default")

    state = (reader or LinuxNetworkStateReader()).read(interface)
    address_entry = _global_ipv4(state)
    address = ipaddress.IPv4Interface(f"{address_entry['local']}/{address_entry['prefixlen']}")
    route = _default_route(state)
    gateway_value = route.get("gateway") if route else None
    try:
        gateway = str(ipaddress.IPv4Address(gateway_value)) if gateway_value else None
    except ipaddress.AddressValueError:
        gateway = None
    permitted, reasons = _active_target_decision(
        address.network,
        active_config.get("approved_ranges"),
        active_config.get("max_hosts"),
    )
    flags = address_entry.get("flags", ())
    dynamic = address_entry.get("dynamic") is True or (
        isinstance(flags, list) and "dynamic" in flags
    )
    route_source_value = route.get("protocol") if route else None
    route_source = route_source_value if isinstance(route_source_value, str) else None
    metric_value = route.get("metric") if route else None
    route_metric = metric_value if isinstance(metric_value, int) else None
    return SubnetDescription(
        interface=interface,
        address=str(address.ip),
        cidr=str(address.network),
        gateway=gateway,
        dns_servers=_dns_servers(state.resolv_conf),
        address_source="dhcp" if dynamic else "kernel",
        route_source=route_source,
        route_metric=route_metric,
        active_target_permitted=permitted,
        active_target_reasons=reasons,
    )
