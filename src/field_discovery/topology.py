"""Deterministic provenance-aware topology inference and diagram rendering."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape as xml_escape
from typing import Any

from field_discovery.passive import PassiveObservation


class TopologyError(ValueError):
    """Topology evidence or requested relationship is invalid."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise TopologyError("topology evidence timestamp must be timezone-aware")
    return value.astimezone(UTC)


def _text(value: object, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise TopologyError(f"{field} must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or "\x00" in normalized:
        raise TopologyError(f"{field} is empty or exceeds {maximum} characters")
    return normalized


def node_id(kind: str, identity: str) -> str:
    """Return a stable opaque diagram identifier without leaking raw identity."""
    normalized_kind = _text(kind, "node kind", 64).casefold()
    normalized_identity = _text(identity, "node identity").casefold()
    digest = hashlib.sha256(f"{normalized_kind}:{normalized_identity}".encode()).hexdigest()[:16]
    return f"n_{normalized_kind}_{digest}"


@dataclass(frozen=True)
class SubnetEvidence:
    cidr: str
    source: str
    observed_at: datetime
    confidence: float = 1.0
    valid_until: datetime | None = None

    def __post_init__(self) -> None:
        try:
            network = ipaddress.ip_network(self.cidr, strict=True)
        except ValueError as exc:
            raise TopologyError("subnet CIDR must be canonical") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise TopologyError("topology currently supports IPv4 subnets only")
        object.__setattr__(self, "cidr", str(network))
        object.__setattr__(self, "source", _text(self.source, "subnet source", 128))
        object.__setattr__(self, "observed_at", _utc(self.observed_at))
        if self.valid_until is not None:
            object.__setattr__(
                self, "valid_until", _valid_until(self.valid_until, self.observed_at)
            )
        _confidence(self.confidence)


@dataclass(frozen=True)
class VlanEvidence:
    vlan_id: int
    source: str
    observed_at: datetime
    subnet_cidr: str | None = None
    name: str | None = None
    confidence: float = 1.0
    valid_until: datetime | None = None

    def __post_init__(self) -> None:
        if isinstance(self.vlan_id, bool) or not 0 <= self.vlan_id <= 4094:
            raise TopologyError("VLAN ID must be from 0 to 4094")
        object.__setattr__(self, "source", _text(self.source, "VLAN source", 128))
        object.__setattr__(self, "observed_at", _utc(self.observed_at))
        if self.valid_until is not None:
            object.__setattr__(
                self, "valid_until", _valid_until(self.valid_until, self.observed_at)
            )
        if self.name is not None:
            object.__setattr__(self, "name", _text(self.name, "VLAN name", 128))
        if self.subnet_cidr is not None:
            try:
                network = ipaddress.ip_network(self.subnet_cidr, strict=True)
            except ValueError as exc:
                raise TopologyError("VLAN subnet CIDR must be canonical") from exc
            if not isinstance(network, ipaddress.IPv4Network):
                raise TopologyError("VLAN subnet must be IPv4")
            object.__setattr__(self, "subnet_cidr", str(network))
        _confidence(self.confidence)


@dataclass(frozen=True)
class TopologyNode:
    node_id: str
    kind: str
    label: str


@dataclass(frozen=True)
class TopologyEdge:
    source_node: str
    target_node: str
    kind: str
    evidence_source: str
    confidence: float
    inferred: bool
    observed_at: datetime
    valid_until: datetime | None = None

    def __post_init__(self) -> None:
        if self.source_node == self.target_node:
            raise TopologyError("topology self-edges are not allowed")
        object.__setattr__(self, "kind", _text(self.kind, "edge kind", 128))
        object.__setattr__(
            self, "evidence_source", _text(self.evidence_source, "edge evidence source", 128)
        )
        _confidence(self.confidence)
        object.__setattr__(self, "observed_at", _utc(self.observed_at))
        if self.valid_until is not None:
            object.__setattr__(
                self, "valid_until", _valid_until(self.valid_until, self.observed_at)
            )


@dataclass(frozen=True)
class TopologyConflict:
    kind: str
    subject: str
    details: tuple[str, ...]
    sources: tuple[str, ...]


@dataclass(frozen=True)
class TopologyGraph:
    nodes: tuple[TopologyNode, ...]
    edges: tuple[TopologyEdge, ...]
    conflicts: tuple[TopologyConflict, ...]
    as_of: datetime | None = None
    excluded_expired: int = 0
    excluded_future: int = 0
    limitations: tuple[str, ...] = ()


def _confidence(value: float) -> None:
    if isinstance(value, bool) or not 0.0 <= value <= 1.0:
        raise TopologyError("confidence must be between 0 and 1")


def _valid_until(value: datetime, observed_at: datetime) -> datetime:
    normalized = _utc(value)
    if normalized < observed_at:
        raise TopologyError("valid_until must not precede observed_at")
    return normalized


class _Builder:
    def __init__(self, as_of: datetime) -> None:
        self.as_of = as_of
        self.nodes: dict[str, TopologyNode] = {}
        self.edges: dict[tuple[str, str, str, str], TopologyEdge] = {}
        self.conflicts: list[TopologyConflict] = []
        self.excluded_expired = 0
        self.excluded_future = 0

    def node(self, kind: str, identity: str, label: str | None = None) -> str:
        identifier = node_id(kind, identity)
        candidate = TopologyNode(identifier, kind, _text(label or identity, "node label"))
        previous = self.nodes.get(identifier)
        if previous is None or candidate.label.casefold() < previous.label.casefold():
            self.nodes[identifier] = candidate
        return identifier

    def edge(self, edge: TopologyEdge) -> None:
        key = (edge.source_node, edge.target_node, edge.kind, edge.evidence_source)
        previous = self.edges.get(key)
        if previous is None or (
            edge.confidence,
            edge.observed_at,
            edge.valid_until or datetime.max.replace(tzinfo=UTC),
        ) > (
            previous.confidence,
            previous.observed_at,
            previous.valid_until or datetime.max.replace(tzinfo=UTC),
        ):
            self.edges[key] = edge

    def active(self, observed_at: datetime, valid_until: datetime | None) -> bool:
        if observed_at > self.as_of:
            self.excluded_future += 1
            return False
        if valid_until is not None and valid_until <= self.as_of:
            self.excluded_expired += 1
            return False
        return True

    def result(self) -> TopologyGraph:
        limitations: list[str] = []
        if self.excluded_expired:
            limitations.append(
                f"{self.excluded_expired} expired evidence item(s) were excluded from the active "
                f"topology as of {self.as_of.isoformat()}."
            )
        if self.excluded_future:
            limitations.append(
                f"{self.excluded_future} future-dated evidence item(s) were excluded from the "
                f"topology as of {self.as_of.isoformat()}."
            )
        return TopologyGraph(
            tuple(sorted(self.nodes.values(), key=lambda item: item.node_id)),
            tuple(
                sorted(
                    self.edges.values(),
                    key=lambda item: (
                        item.source_node,
                        item.target_node,
                        item.kind,
                        item.evidence_source,
                    ),
                )
            ),
            tuple(sorted(self.conflicts, key=lambda item: (item.kind, item.subject, item.details))),
            self.as_of,
            self.excluded_expired,
            self.excluded_future,
            tuple(limitations),
        )


def _observed_at(observation: PassiveObservation) -> datetime:
    if observation.observed_at is None:
        raise TopologyError("topology observations require an observed_at timestamp")
    return _utc(observation.observed_at)


def _expires_at(observation: PassiveObservation) -> datetime | None:
    return None if observation.expires_at is None else _utc(observation.expires_at)


def _string(fields: dict[str, Any], key: str) -> str | None:
    value = fields.get(key)
    return value if isinstance(value, str) and value.strip() else None


def _device_node(builder: _Builder, identity_kind: str, identity: str, label: str | None) -> str:
    return builder.node("device", f"{identity_kind}:{identity.casefold()}", label or identity)


def _subnet_for(address: str, subnets: tuple[SubnetEvidence, ...]) -> SubnetEvidence | None:
    try:
        parsed = ipaddress.IPv4Address(address)
    except ipaddress.AddressValueError:
        return None
    matches = [item for item in subnets if parsed in ipaddress.IPv4Network(item.cidr)]
    if not matches:
        return None
    return max(matches, key=lambda item: ipaddress.IPv4Network(item.cidr).prefixlen)


def build_topology(
    observations: Iterable[PassiveObservation],
    *,
    local_identity: str,
    as_of: datetime | None = None,
    local_label: str | None = None,
    subnets: Iterable[SubnetEvidence] = (),
    vlans: Iterable[VlanEvidence] = (),
) -> TopologyGraph:
    """Build deterministic observed/inferred topology from normalized passive facts."""
    if as_of is None:
        raise TopologyError("an explicit as_of timestamp is required for active topology")
    snapshot = _utc(as_of)
    builder = _Builder(snapshot)
    local = _device_node(builder, "local", _text(local_identity, "local identity"), local_label)
    subnet_items = tuple(
        item
        for item in sorted(subnets, key=lambda item: item.cidr)
        if builder.active(item.observed_at, item.valid_until)
    )
    vlan_items = tuple(
        item
        for item in sorted(vlans, key=lambda item: (item.vlan_id, item.source))
        if builder.active(item.observed_at, item.valid_until)
    )
    subnet_nodes: dict[str, str] = {}
    for subnet in subnet_items:
        subnet_nodes[subnet.cidr] = builder.node("subnet", subnet.cidr)
    vlan_nodes: dict[int, str] = {}
    for vlan in vlan_items:
        vlan_node = builder.node(
            "vlan",
            str(vlan.vlan_id),
            f"VLAN {vlan.vlan_id}" + (f" — {vlan.name}" if vlan.name else ""),
        )
        vlan_nodes[vlan.vlan_id] = vlan_node
        if vlan.subnet_cidr is not None:
            subnet_node = subnet_nodes.get(vlan.subnet_cidr) or builder.node(
                "subnet", vlan.subnet_cidr
            )
            subnet_nodes[vlan.subnet_cidr] = subnet_node
            builder.edge(
                TopologyEdge(
                    vlan_node,
                    subnet_node,
                    "vlan_subnet",
                    vlan.source,
                    vlan.confidence,
                    False,
                    vlan.observed_at,
                    vlan.valid_until,
                )
            )

    ordered_observations = sorted(
        observations,
        key=lambda item: (
            _observed_at(item).isoformat(),
            item.kind,
            item.source,
            json.dumps(item.fields, sort_keys=True, separators=(",", ":")),
        ),
    )
    vlan_claims: dict[str, list[tuple[int, str]]] = defaultdict(list)
    for observation in ordered_observations:
        observed_at = _observed_at(observation)
        valid_until = (
            None
            if observation.expires_at is None
            else _valid_until(observation.expires_at, observed_at)
        )
        if not builder.active(observed_at, valid_until):
            continue
        fields = dict(observation.fields)
        if observation.kind == "link_layer_neighbor":
            _link_layer(builder, local, fields, observation, vlan_nodes, vlan_claims)
        elif observation.kind in {"mdns_service", "mdns_instance", "mdns_address"}:
            _mdns(builder, fields, observation, subnet_items, subnet_nodes)
        elif observation.kind == "dhcp_message":
            _dhcp(builder, fields, observation, subnet_items, subnet_nodes)
        elif observation.kind == "neighbor_observation":
            _neighbor(builder, fields, observation, subnet_items, subnet_nodes)
        elif observation.kind in {
            "dhcp_address_reuse",
            "neighbor_ip_reuse",
            "neighbor_mac_movement",
        }:
            details = tuple(
                f"{key}={json.dumps(value, sort_keys=True)}"
                for key, value in sorted(fields.items())
            )
            builder.conflicts.append(
                TopologyConflict(
                    observation.kind,
                    _string(fields, "address") or "unspecified",
                    details,
                    (observation.source,),
                )
            )
    for subject, claims in sorted(vlan_claims.items()):
        values = tuple(sorted({value for value, _source in claims}))
        if len(values) > 1:
            builder.conflicts.append(
                TopologyConflict(
                    "vlan_disagreement",
                    subject,
                    tuple(str(value) for value in values),
                    tuple(sorted({source for _value, source in claims})),
                )
            )
    return builder.result()


def _link_layer(
    builder: _Builder,
    local: str,
    fields: dict[str, Any],
    observation: PassiveObservation,
    vlan_nodes: dict[int, str],
    vlan_claims: dict[str, list[tuple[int, str]]],
) -> None:
    chassis = _string(fields, "chassis_id")
    port = _string(fields, "port_id")
    if chassis is None or port is None:
        builder.conflicts.append(
            TopologyConflict(
                "incomplete_link_evidence",
                observation.source,
                ("missing chassis_id or port_id",),
                (observation.source,),
            )
        )
        return
    subtype = _string(fields, "chassis_id_subtype") or "chassis"
    label = _string(fields, "system_name") or chassis
    remote = _device_node(builder, subtype, chassis, label)
    builder.edge(
        TopologyEdge(
            local,
            remote,
            "link_layer_neighbor",
            observation.source,
            0.99,
            False,
            _observed_at(observation),
            _expires_at(observation),
        )
    )
    vlan_value = fields.get("vlan_id")
    if not isinstance(vlan_value, int) or isinstance(vlan_value, bool):
        return
    if not 0 <= vlan_value <= 4094:
        return
    vlan_node = vlan_nodes.get(vlan_value) or builder.node(
        "vlan", str(vlan_value), f"VLAN {vlan_value}"
    )
    vlan_nodes[vlan_value] = vlan_node
    builder.edge(
        TopologyEdge(
            remote,
            vlan_node,
            "observed_vlan",
            observation.source,
            0.95,
            False,
            _observed_at(observation),
            _expires_at(observation),
        )
    )
    vlan_claims[remote].append((vlan_value, observation.source))


def _active_mdns(fields: dict[str, Any]) -> bool:
    action = fields.get("action", "announce")
    return isinstance(action, str) and action == "announce"


def _mdns(
    builder: _Builder,
    fields: dict[str, Any],
    observation: PassiveObservation,
    subnets: tuple[SubnetEvidence, ...],
    subnet_nodes: dict[str, str],
) -> None:
    if not _active_mdns(fields):
        return
    timestamp = _observed_at(observation)
    if observation.kind == "mdns_service":
        service_type = _string(fields, "service_type")
        instance = _string(fields, "instance")
        if service_type is None or instance is None:
            return
        service_node = builder.node("service", service_type)
        instance_node = builder.node("service_instance", instance)
        builder.edge(
            TopologyEdge(
                service_node,
                instance_node,
                "advertises",
                observation.source,
                0.95,
                False,
                timestamp,
                _expires_at(observation),
            )
        )
        return
    if observation.kind == "mdns_instance":
        instance = _string(fields, "instance")
        hostname = _string(fields, "hostname")
        if instance is None or hostname is None:
            return
        instance_node = builder.node("service_instance", instance)
        host_node = _device_node(builder, "hostname", hostname, hostname)
        builder.edge(
            TopologyEdge(
                instance_node,
                host_node,
                "service_host",
                observation.source,
                0.95,
                False,
                timestamp,
                _expires_at(observation),
            )
        )
        return
    hostname = _string(fields, "hostname")
    address = _string(fields, "address")
    if hostname is None or address is None:
        return
    host_node = _device_node(builder, "hostname", hostname, hostname)
    _membership(
        builder,
        host_node,
        address,
        observation.source,
        0.70,
        timestamp,
        _expires_at(observation),
        subnets,
        subnet_nodes,
    )


def _dhcp(
    builder: _Builder,
    fields: dict[str, Any],
    observation: PassiveObservation,
    subnets: tuple[SubnetEvidence, ...],
    subnet_nodes: dict[str, str],
) -> None:
    if fields.get("message_type") != "ack":
        return
    address = _string(fields, "assigned_address")
    client_mac = _string(fields, "client_mac")
    client_identifier = _string(fields, "client_identifier")
    if address is None or (client_mac is None and client_identifier is None):
        return
    identity_kind = "mac" if client_mac is not None else "dhcp_client_id"
    identity = client_mac or client_identifier
    assert identity is not None
    client = _device_node(builder, identity_kind, identity, _string(fields, "hostname") or identity)
    timestamp = _observed_at(observation)
    _membership(
        builder,
        client,
        address,
        observation.source,
        0.90,
        timestamp,
        _expires_at(observation),
        subnets,
        subnet_nodes,
    )
    server = _string(fields, "server_identifier")
    if server is not None:
        server_node = _device_node(builder, "ipv4_observation", server, f"DHCP {server}")
        builder.edge(
            TopologyEdge(
                server_node,
                client,
                "dhcp_lease",
                observation.source,
                0.90,
                False,
                timestamp,
                _expires_at(observation),
            )
        )


def _neighbor(
    builder: _Builder,
    fields: dict[str, Any],
    observation: PassiveObservation,
    subnets: tuple[SubnetEvidence, ...],
    subnet_nodes: dict[str, str],
) -> None:
    address = _string(fields, "address")
    mac = _string(fields, "mac_address")
    if address is None or mac is None:
        return
    device = _device_node(builder, "mac", mac, mac)
    _membership(
        builder,
        device,
        address,
        observation.source,
        0.75,
        _observed_at(observation),
        _expires_at(observation),
        subnets,
        subnet_nodes,
    )


def _membership(
    builder: _Builder,
    device: str,
    address: str,
    source: str,
    confidence: float,
    observed_at: datetime,
    valid_until: datetime | None,
    subnets: tuple[SubnetEvidence, ...],
    subnet_nodes: dict[str, str],
) -> None:
    subnet = _subnet_for(address, subnets)
    if subnet is None:
        return
    subnet_node = subnet_nodes[subnet.cidr]
    builder.edge(
        TopologyEdge(
            device,
            subnet_node,
            "inferred_subnet_membership",
            source,
            min(confidence, subnet.confidence),
            True,
            observed_at,
            valid_until,
        )
    )


def graphviz_source(graph: TopologyGraph) -> str:
    """Return deterministic standalone Graphviz DOT source with visible provenance."""
    lines = ["digraph codexnet {", "  rankdir=LR;", "  graph [bgcolor=white];"]
    shapes = {"device": "box", "subnet": "oval", "vlan": "hexagon", "service": "component"}
    for node in graph.nodes:
        shape = shapes.get(node.kind, "ellipse")
        label = f"{node.label}\\n[{node.kind}]"
        lines.append(f"  {node.node_id} [shape={shape},label={json.dumps(label)}];")
    for edge in graph.edges:
        status = "inferred" if edge.inferred else "observed"
        validity = edge.valid_until.isoformat() if edge.valid_until is not None else "open"
        label = (
            f"{edge.kind}\\n{edge.evidence_source} {edge.confidence:.2f} {status} until={validity}"
        )
        style = "dashed" if edge.inferred else "solid"
        lines.append(
            f"  {edge.source_node} -> {edge.target_node} [style={style},label={json.dumps(label)}];"
        )
    for index, conflict in enumerate(graph.conflicts):
        label = f"CONFLICT: {conflict.kind}\\n{conflict.subject}\\n" + ", ".join(conflict.details)
        lines.append(
            f"  conflict_{index:04d} "
            f"[shape=note,color=red,fontcolor=red,label={json.dumps(label)}];"
        )
    for index, limitation in enumerate(graph.limitations):
        lines.append(
            f"  limitation_{index:04d} "
            f"[shape=note,color=orange,label={json.dumps('LIMITATION: ' + limitation)}];"
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def mermaid_source(graph: TopologyGraph) -> str:
    """Return deterministic Mermaid source with edge provenance/confidence labels."""
    lines = ["flowchart LR"]
    for node in graph.nodes:
        label = node.label.replace('"', "'")
        lines.append(f'  {node.node_id}["{label}<br/>[{node.kind}]"]')
    for edge in graph.edges:
        status = "inferred" if edge.inferred else "observed"
        validity = edge.valid_until.isoformat() if edge.valid_until is not None else "open"
        label = (
            f"{edge.kind}; {edge.evidence_source}; {edge.confidence:.2f}; {status}; "
            f"until={validity}"
        )
        connector = "-.->" if edge.inferred else "-->"
        lines.append(f"  {edge.source_node} {connector}|{label}| {edge.target_node}")
    for index, conflict in enumerate(graph.conflicts):
        label = f"CONFLICT: {conflict.kind} — {conflict.subject}".replace('"', "'")
        lines.append(f'  conflict_{index:04d}["{label}"]')
        lines.append(f"  style conflict_{index:04d} fill:#fee,stroke:#c00,color:#900")
    for index, limitation in enumerate(graph.limitations):
        label = ("LIMITATION: " + limitation).replace('"', "'")
        lines.append(f'  limitation_{index:04d}["{label}"]')
    return "\n".join(lines) + "\n"


def render_svg(graph: TopologyGraph) -> str:
    """Render a self-contained deterministic SVG without external resources."""
    positions = {
        node.node_id: (80 + (index % 3) * 360, 60 + (index // 3) * 150)
        for index, node in enumerate(graph.nodes)
    }
    rows = (len(graph.nodes) + 2) // 3
    conflict_y = 80 + rows * 150
    annotation_count = len(graph.conflicts) + len(graph.limitations)
    height = max(240, conflict_y + max(1, annotation_count) * 45 + 40)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{height}" '
        'viewBox="0 0 1200 {height}" role="img">'.format(height=height),
        "<title>CodexNet topology</title>",
        '<rect width="100%" height="100%" fill="white"/>',
    ]
    for edge in graph.edges:
        x1, y1 = positions[edge.source_node]
        x2, y2 = positions[edge.target_node]
        dash = ' stroke-dasharray="6 4"' if edge.inferred else ""
        parts.append(
            f'<line x1="{x1 + 130}" y1="{y1 + 30}" x2="{x2 + 130}" y2="{y2 + 30}" '
            f'stroke="#555"{dash}/>'
        )
        validity = edge.valid_until.isoformat() if edge.valid_until is not None else "open"
        label = xml_escape(
            f"{edge.kind} · {edge.evidence_source} · {edge.confidence:.2f} · until {validity}"
        )
        parts.append(
            f'<text x="{(x1 + x2) // 2 + 130}" y="{(y1 + y2) // 2 + 20}" '
            f'font-size="11" text-anchor="middle">{label}</text>'
        )
    for node in graph.nodes:
        x, y = positions[node.node_id]
        parts.append(
            f'<rect x="{x}" y="{y}" width="260" height="60" rx="8" fill="#eef5ff" stroke="#345"/>'
        )
        parts.append(
            f'<text x="{x + 130}" y="{y + 25}" font-size="14" text-anchor="middle">'
            f"{xml_escape(node.label)}</text>"
        )
        parts.append(
            f'<text x="{x + 130}" y="{y + 45}" font-size="11" text-anchor="middle" '
            f'fill="#555">[{xml_escape(node.kind)}]</text>'
        )
    for index, conflict in enumerate(graph.conflicts):
        text = xml_escape(f"CONFLICT: {conflict.kind} — {conflict.subject}")
        parts.append(
            f'<text x="80" y="{conflict_y + index * 45}" font-size="14" fill="#a00">{text}</text>'
        )
    limitation_y = conflict_y + len(graph.conflicts) * 45
    for index, limitation in enumerate(graph.limitations):
        text = xml_escape("LIMITATION: " + limitation)
        parts.append(
            f'<text x="80" y="{limitation_y + index * 45}" font-size="13" fill="#964b00">'
            f"{text}</text>"
        )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def diagram_digest(content: str) -> str:
    """Return the stable SHA-256 used by deterministic-output checks."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
