# UniFi and Active Directory report enrichment

T504 adds deterministic, source-labelled UniFi and Active Directory sections to the
normalized report model and the interim self-contained DOCX renderer.

## UniFi section

The report groups controller inventory by controller and site, then renders site,
switch, access-point, gateway, network, WLAN, client, and unresolved-endpoint nodes
from the normalized UniFi tables. Controller relationships become diagram edges.
Every node and edge carries its observation source and timestamp; entity rows also
show evidence age. Permission failures and endpoint-specific coverage omissions are
listed separately so missing API data is not represented as an observed absence.

## Active Directory section

The report renders the documented domain/forest identity and allowlisted directory
entities. Domain, site, subnet, domain-controller, server-role, and trust records form
the AD graph. A subnet is attached to its matching site using the normalized
`siteObject` distinguished name; an unmatched subnet remains visibly attached to its
domain rather than being silently discarded. Trust direction and type are included
as documented values, not interpreted as attack-path data.

## Safety and determinism

Only explicitly selected normalized fields enter either report section. Arbitrary
UniFi attributes and AD attribute dictionaries are not copied to JSON, Mermaid, or
DOCX. In particular, password, hash, ticket, secret, and attack-path attributes are
never report fields. The repository redactor is applied to the complete report model
before serialization, covering labels, collector permission details, JSON, diagram
source, and unzipped DOCX XML.

Diagram identifiers are stable opaque hashes, while nodes and edges are sorted by
stable identifiers and relationship metadata. Given the same database and generation
timestamp, JSON, Mermaid source, and DOCX bytes are reproducible. Unresolved or
cross-deployment UniFi endpoints receive an opaque placeholder and never disclose
another deployment's inventory.

The primary verification is `tests/test_platform_reporting.py`. It covers fixture
graphs, deployment isolation, coverage/permission notes, evidence age, malformed
stored values, forbidden-attribute omission, and redaction across JSON, Mermaid, and
unzipped DOCX XML.
