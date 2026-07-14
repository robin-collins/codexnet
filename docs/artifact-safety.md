# Artifact safety contract

`field_discovery.artifacts.ArtifactStore` is the required boundary for collector diagnostic text
and JSON artifacts. It accepts a real mode-`0700` directory, publishes mode-`0600` files without
following links, never replaces an existing basename, applies the central `Redactor`, and rejects
content over its configured byte limit. Tests and callers must point it at temporary or configured
application-owned directories, never the protected nmap or Scanopy data stores.

Each artifact has a deterministic JSON metadata sidecar recording schema version, safe basename,
category, media type, byte size, SHA-256 digest, creation time, and expiry time. Metadata contains no
source label, customer identifier, credential reference, target, or raw content. The retention hook
lists expired files and defaults to a dry run. Explicit deletion rechecks that both entries are
regular files and refuses links or special files.

`safe_filename` creates bounded portable basenames for caller-supplied labels; direct store calls
also validate the final basename and reject traversal, absolute paths, hidden files, separators, and
reserved metadata names. Register resolved ephemeral secrets with the store's `Redactor` before any
artifact is written. Binary report publication is deliberately not accepted here: DOCX and rendered
diagram output requires its later format-specific validation before atomic publication.

`audit_outputs` provides the seeded-secret and structural-pattern check used against test logs,
sanitized database JSON exports, and generated text artifacts. It treats symlinks and over-limit
files as findings. Later report validation extends this boundary to ZIP members and DOCX XML.
