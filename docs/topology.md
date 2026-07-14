# Topology inference and diagrams

`field_discovery.topology` builds a deterministic graph from normalized passive observations. LLDP
and CDP create observed local-to-neighbour links. DNS-SD PTR/SRV records create observed
service-to-instance-to-host relationships. DHCP ACK and ARP/kernel-neighbour facts can place a
stable client identity into an explicitly supplied subnet; those membership edges are marked as
inference. Explicit VLAN-to-subnet configuration and observed link-layer VLAN claims remain
source-labelled facts.

Every edge carries its source, confidence, observation time, and observed/inferred flag. Hostnames
and addresses do not merge nodes with MAC/chassis identities. Evidence without the identifiers
required for a relationship is omitted rather than rendered as a fact. Address reuse, MAC movement,
DHCP reuse, incomplete links, and contradictory VLAN claims remain visible conflict annotations.

Node and edge ordering, opaque identifiers, labels, numeric confidence formatting, and diagram
layout are deterministic. The module emits standalone Graphviz DOT and Mermaid source plus a
self-contained SVG renderer with no network, browser, shell, font, or external-resource dependency.
Rendered edges display source and confidence, and inferred edges use a dashed style.
