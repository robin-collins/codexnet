# Safe Active Directory detection

`discover ad` identifies likely domain controllers without usernames, passwords, tickets, hashes,
or other authentication material. Detection accepts only explicit command-line domains or the
configured non-secret AD domain. Domains are normalized as qualified ASCII DNS names; wildcards,
SRV owner names, search-list expansion, malformed labels, and more than 16 domains are rejected.

For each approved domain the detector performs bounded queries for:

- `_ldap._tcp.dc._msdcs.<domain>`;
- `_kerberos._tcp.<domain>`; and
- `_ldap._tcp.<site>._sites.dc._msdcs.<domain>` for explicitly supplied sites.

SRV targets must remain beneath the approved domain. They are resolved only to IPv4 addresses,
and every address must fall inside `active.approved_ranges` before any RootDSE connection occurs.
Malformed, oversized, unreachable, out-of-domain, and out-of-range results become explicit
limitations; they do not broaden the target set or stop other domain candidates.

The detector also reads existing open service evidence already in the CodexNet repository. This
is a local database read, not a probe. Hostnames must belong to an approved domain, addresses must
be valid IPv4, and only documented AD ports/service names can contribute evidence.

## RootDSE boundary

The live adapter creates an anonymous LDAP connection and issues exactly one base-scope search at
the empty DN with `(objectClass=*)`. It requests only this fixed metadata allowlist:

- naming contexts for the domain, root domain, configuration, and schema;
- DNS hostname;
- naming-context list; and
- supported-capability OIDs.

No credential argument exists in the RootDSE adapter protocol or detector API. The response is
bounded and rejected if it contains unknown attributes, non-text values, excessive values, a
default naming context for another domain, or no recognised AD capability OID. LDAP port 389 is
used for metadata-only detection unless existing evidence explicitly identifies LDAPS 636. T503
owns authenticated Kerberos/LDAPS directory collection and its separate attribute denylist.

DNS LDAP SRV evidence produces a conservative candidate at confidence 0.8. A matching RootDSE AD
capability raises confidence to 0.98. Kerberos-only or generic service evidence is never emitted as
an AD candidate unless RootDSE confirms the approved domain. Sources, site scope, addresses,
ports, confidence, and all limitations are retained as provenance-aware observations.

## Offline verification

Tests use synthetic DNS, service, and LDAP sessions only. The fixture matrix covers AD and non-AD
DNS, multiple domains and DCs, site SRV records, unreachable DNS/RootDSE, malformed and oversized
records, target refusal, anonymous LDAP operation shape, persistence, deterministic ordering, and
partial failure isolation. No test contacts a live network.
