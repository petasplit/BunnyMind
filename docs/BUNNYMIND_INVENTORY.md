# BunnyMind v0.6: incremental inventory graph

Inspired by the attack-surface inventory approach described by BugBunny and
the graph-based state model used by RedAmon, but independently implemented in Go.

The offline agent tool `inventory_graph` accepts a **caller-supplied** list of
assets and relationships and compares it with the last snapshot for the
same Antares session. It does not crawl, scan or fetch live sites.

## Model

- Asset types: origin, endpoint, service, technology, repository, dependency.
- Relationship types: contains, calls, depends_on, protected_by, resolves_to.
- Stable IDs and a SHA-256 fingerprint provided by the caller.
- Source labels explicitly distinguish `captured_http`, `source_inventory`,
  `user_supplied`, and `inferred`. None is independent proof of accuracy.
- Snapshot validation rejects duplicate IDs, dangling links, invalid hash
  syntax, URL query parameters, credentials and fragments in URL-shaped keys.
- Per-session files use a SHA-256-derived filename, 0600 file permissions,
  and atomic replacement. This store is single-process safe, not a
  distributed graph database.

## Actions

`update`: Saves the next versioned snapshot and returns an ID-only diff,
listing added, removed, modified and unchanged assets, plus added/removed
relationships. The snapshot may be empty to represent a completely
retracted caller-supplied inventory.

`status`: Summarizes asset and edge counts and source distributions without
returning the raw asset keys.

## Operational role

The agent can use the difference set to prioritize review of changes and
avoid declaring unchanged assets newly discovered. Nothing automatically
uses or schedules the diff yet: later integration with BunnyHarness is
required to produce dependency-aware review jobs.

## Trust/accuracy

Assets must be populated by trusted instrumentation if the result is to
support a security assertion. A model can supply invented fingerprints; this
tool would still compute a valid structural diff. Source labels are **not
attestations**. Data from endpoints is untrusted and cannot override
the engagement scope. Do not persist credentials, PII or live session
information in graph keys.

Run `go test ./internal/bunnygraph ./internal/tools`.
