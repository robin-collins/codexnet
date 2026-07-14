"""Deterministic provenance-aware topology and diagram tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from field_discovery.passive import JsonValue, PassiveObservation
from field_discovery.topology import (
    SubnetEvidence,
    TopologyEdge,
    TopologyError,
    TopologyGraph,
    TopologyNode,
    VlanEvidence,
    build_topology,
    diagram_digest,
    graphviz_source,
    mermaid_source,
    node_id,
    render_svg,
)

NOW = datetime(2026, 7, 15, 2, tzinfo=UTC)
FIXTURE = Path(__file__).parent / "fixtures/topology/observations.json"


def observations() -> tuple[PassiveObservation, ...]:
    document = json.loads(FIXTURE.read_text())
    return tuple(
        PassiveObservation(
            item["kind"],
            item["fields"],
            item["source"],
            observed_at=datetime.fromisoformat(item["observed_at"].replace("Z", "+00:00")),
        )
        for item in document
    )


def fixture_graph(items: tuple[PassiveObservation, ...] | None = None) -> TopologyGraph:
    return build_topology(
        observations() if items is None else items,
        local_identity="codexnet-pi",
        local_label="CodexNet Pi",
        subnets=(SubnetEvidence("192.168.50.0/24", "resolver", NOW, 0.98),),
        vlans=(VlanEvidence(10, "site-config", NOW, "192.168.50.0/24", "Users", 1.0),),
    )


def test_fixture_has_expected_nodes_edges_conflicts_and_provenance() -> None:
    graph = fixture_graph()
    assert len(graph.nodes) == 10
    assert len(graph.edges) == 11
    assert [item.kind for item in graph.conflicts] == [
        "incomplete_link_evidence",
        "neighbor_ip_reuse",
        "vlan_disagreement",
    ]
    assert {item.kind for item in graph.edges} == {
        "advertises",
        "dhcp_lease",
        "inferred_subnet_membership",
        "link_layer_neighbor",
        "observed_vlan",
        "service_host",
        "vlan_subnet",
    }
    assert all(item.evidence_source and 0 <= item.confidence <= 1 for item in graph.edges)
    inferred = [item for item in graph.edges if item.inferred]
    assert len(inferred) == 3
    assert {item.evidence_source for item in inferred} == {
        "kernel.neighbor",
        "mdns",
        "passive.dhcp",
    }
    vlan_conflict = graph.conflicts[-1]
    assert vlan_conflict.details == ("10", "20")
    assert vlan_conflict.sources == ("passive:cdp", "passive:lldp")


def test_input_order_and_repeated_evidence_produce_stable_hash() -> None:
    items = observations()
    forward = fixture_graph(items)
    reverse = fixture_graph(tuple(reversed(items)))
    duplicate = fixture_graph((*items, items[0]))
    assert forward == reverse == duplicate
    dot = graphviz_source(forward)
    assert diagram_digest(dot) == diagram_digest(graphviz_source(reverse))
    assert diagram_digest(dot) == "6f073c697828c626f17f221581c63bcc8e9219f67265b914ad41dd134dbf8b16"


def test_graphviz_mermaid_and_svg_show_inference_provenance_and_conflicts() -> None:
    graph = fixture_graph()
    dot = graphviz_source(graph)
    mermaid = mermaid_source(graph)
    svg = render_svg(graph)
    assert dot.startswith("digraph codexnet") and dot.endswith("}\n")
    assert "passive.dhcp 0.90 observed" in dot
    assert "kernel.neighbor 0.75 inferred" in dot
    assert "style=dashed" in dot
    assert "CONFLICT: vlan_disagreement" in dot
    assert mermaid.startswith("flowchart LR\n")
    assert "-.->|inferred_subnet_membership;" in mermaid
    assert "CONFLICT: neighbor_ip_reuse" in mermaid
    root = ET.fromstring(svg)
    assert root.tag == "{http://www.w3.org/2000/svg}svg"
    assert "http://" not in svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
    assert "https://" not in svg
    assert "kernel.neighbor · 0.75" in svg
    assert "CONFLICT: vlan_disagreement" in svg
    assert render_svg(graph) == svg


def test_unknown_or_incomplete_evidence_never_becomes_a_topology_fact() -> None:
    items = (
        PassiveObservation("link_layer_neighbor", {"port_id": "p1"}, "lldp", observed_at=NOW),
        PassiveObservation(
            "neighbor_observation",
            {"address": "192.168.50.2", "mac_address": None},
            "kernel.neighbor",
            observed_at=NOW,
        ),
        PassiveObservation(
            "dhcp_message",
            {"message_type": "ack", "assigned_address": "192.168.50.2"},
            "dhcp",
            observed_at=NOW,
        ),
        PassiveObservation(
            "mdns_address",
            {"hostname": "gone.local", "address": "192.168.50.2", "action": "expired"},
            "mdns",
            observed_at=NOW,
        ),
    )
    graph = fixture_graph(items)
    assert len(graph.nodes) == 3  # local plus explicit subnet and VLAN only
    assert [edge.kind for edge in graph.edges] == ["vlan_subnet"]
    assert graph.conflicts[0].kind == "incomplete_link_evidence"
    assert all("unknown" not in node.node_id for node in graph.nodes)


def test_longest_prefix_subnet_is_selected_and_invalid_addresses_are_not_asserted() -> None:
    item = PassiveObservation(
        "neighbor_observation",
        {"address": "10.0.1.20", "mac_address": "00:11:22:33:44:55"},
        "arp",
        observed_at=NOW,
    )
    graph = build_topology(
        (item,),
        local_identity="pi",
        subnets=(
            SubnetEvidence("10.0.0.0/16", "broad", NOW),
            SubnetEvidence("10.0.1.0/24", "specific", NOW, 0.6),
        ),
    )
    membership = next(edge for edge in graph.edges if edge.kind == "inferred_subnet_membership")
    assert membership.target_node == node_id("subnet", "10.0.1.0/24")
    assert membership.confidence == 0.6

    invalid = PassiveObservation(
        "neighbor_observation",
        {"address": "not-an-ip", "mac_address": "00:11:22:33:44:55"},
        "arp",
        observed_at=NOW,
    )
    assert not build_topology((invalid,), local_identity="pi").edges

    valid_without_subnet = PassiveObservation(
        "neighbor_observation",
        {"address": "10.0.0.2", "mac_address": "00:11:22:33:44:55"},
        "arp",
        observed_at=NOW,
    )
    assert not build_topology((valid_without_subnet,), local_identity="pi").edges


def test_vlan_without_subnet_and_single_claim_do_not_create_conflicts() -> None:
    link = PassiveObservation(
        "link_layer_neighbor",
        {"chassis_id": "switch-1", "port_id": "p1", "vlan_id": 30},
        "lldp",
        observed_at=NOW,
    )
    graph = build_topology(
        (link,),
        local_identity="pi",
        vlans=(
            VlanEvidence(30, "config", NOW, name="Voice"),
            VlanEvidence(40, "config", NOW),
        ),
    )
    assert not graph.conflicts
    assert {edge.kind for edge in graph.edges} == {"link_layer_neighbor", "observed_vlan"}


@pytest.mark.parametrize("vlan_value", [None, True, -1, 4095])
def test_invalid_observed_vlan_is_not_rendered_as_fact(vlan_value: JsonValue) -> None:
    link = PassiveObservation(
        "link_layer_neighbor",
        {"chassis_id": "switch-1", "port_id": "p1", "vlan_id": vlan_value},
        "lldp",
        observed_at=NOW,
    )
    graph = build_topology((link,), local_identity="pi")
    assert [edge.kind for edge in graph.edges] == ["link_layer_neighbor"]


def test_dhcp_client_id_fallback_and_missing_server_are_conservative() -> None:
    item = PassiveObservation(
        "dhcp_message",
        {
            "message_type": "ack",
            "assigned_address": "10.0.0.20",
            "client_mac": None,
            "client_identifier": "ff0011",
            "server_identifier": None,
        },
        "dhcp",
        observed_at=NOW,
    )
    graph = build_topology(
        (item,),
        local_identity="pi",
        subnets=(SubnetEvidence("10.0.0.0/24", "resolver", NOW),),
    )
    assert [edge.kind for edge in graph.edges] == ["inferred_subnet_membership"]
    assert any(node.label == "ff0011" for node in graph.nodes)


def test_missing_mdns_fields_and_unrecognized_observations_are_ignored() -> None:
    items = (
        PassiveObservation("mdns_service", {"service_type": "_x._tcp"}, "mdns", observed_at=NOW),
        PassiveObservation("mdns_instance", {"instance": "x"}, "mdns", observed_at=NOW),
        PassiveObservation("mdns_address", {"hostname": "x"}, "mdns", observed_at=NOW),
        PassiveObservation("something_new", {"unknown": True}, "future", observed_at=NOW),
    )
    graph = build_topology(items, local_identity="pi")
    assert len(graph.nodes) == 1
    assert not graph.edges and not graph.conflicts


@pytest.mark.parametrize(
    ("factory", "message"),
    [
        (lambda: SubnetEvidence("10.0.0.1/24", "source", NOW), "canonical"),
        (lambda: SubnetEvidence("::/64", "source", NOW), "IPv4"),
        (lambda: SubnetEvidence("10.0.0.0/24", "", NOW), "source"),
        (lambda: SubnetEvidence("10.0.0.0/24", "source", datetime(2026, 1, 1)), "timezone"),
        (lambda: SubnetEvidence("10.0.0.0/24", "source", NOW, 2.0), "confidence"),
        (lambda: VlanEvidence(-1, "source", NOW), "VLAN ID"),
        (lambda: VlanEvidence(4095, "source", NOW), "VLAN ID"),
        (lambda: VlanEvidence(10, "", NOW), "source"),
        (lambda: VlanEvidence(10, "source", NOW, name=""), "name"),
        (lambda: VlanEvidence(10, "source", NOW, "bad"), "canonical"),
        (lambda: VlanEvidence(10, "source", NOW, "::/64"), "IPv4"),
        (lambda: VlanEvidence(10, "source", NOW, confidence=-0.1), "confidence"),
    ],
)
def test_subnet_and_vlan_contracts_reject_unsafe_evidence(factory: object, message: str) -> None:
    with pytest.raises(TopologyError, match=message):
        factory()  # type: ignore[operator]


def test_edge_and_node_contracts_reject_invalid_values() -> None:
    with pytest.raises(TopologyError, match="must be text"):
        node_id(1, "identity")  # type: ignore[arg-type]
    with pytest.raises(TopologyError, match="node kind"):
        node_id("", "identity")
    with pytest.raises(TopologyError, match="node identity"):
        node_id("device", "")
    with pytest.raises(TopologyError, match="self-edges"):
        TopologyEdge("same", "same", "kind", "source", 1.0, False, NOW)
    with pytest.raises(TopologyError, match="edge kind"):
        TopologyEdge("a", "b", "", "source", 1.0, False, NOW)
    with pytest.raises(TopologyError, match="evidence source"):
        TopologyEdge("a", "b", "kind", "", 1.0, False, NOW)
    with pytest.raises(TopologyError, match="confidence"):
        TopologyEdge("a", "b", "kind", "source", True, False, NOW)
    with pytest.raises(TopologyError, match="timezone"):
        TopologyEdge("a", "b", "kind", "source", 1.0, False, datetime(2026, 1, 1))
    missing_time = PassiveObservation("unknown", {}, "source")
    with pytest.raises(TopologyError, match="observed_at"):
        build_topology((missing_time,), local_identity="pi")


def test_duplicate_edges_choose_highest_confidence_then_latest() -> None:
    first = TopologyEdge("a", "b", "kind", "source", 0.8, True, NOW)
    graph = TopologyGraph(
        (TopologyNode("a", "device", "A & <one>"), TopologyNode("b", "device", 'B "two"')),
        (first,),
        (),
    )
    assert "A &amp; &lt;one&gt;" in render_svg(graph)
    assert "B 'two'" in mermaid_source(graph)
