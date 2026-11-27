# BunnyMind v0.15 — signed local artifact fingerprint binding

A v0.14 before/after comparison could prove that two sets of signed
synthetic HTTP observations were attributed to different run IDs, but not
which build artifact was associated with either run.

**v0.15 adds local artifact SHA-256 measurements**, signed with the trusted
recorder's Ed25519 key, and an optional `build_sha256` field on every
signed HTTP observation.

## Changes

- `internal/bunnybuild` hashes the actual bytes read from a local regular
  file (maximum 64 MiB) and signs a small record containing engagement,
  run ID, SHA-256, byte count and timestamp. Symlinks, directories, empty
  files and oversize files are refused. The file path and contents are
  never included in the signed record.
- The existing receipt format accepts an optional `build_sha256` field.
  New comparisons reject mixed build fingerprints within a single signed
  receipt bundle. Earlier receipt bundles without a fingerprint remain
  compatible with the v0.14 tools.
- `bunnylab` can bind a configured fingerprint to signed, loopback-only
  HTTP responses; `bunnyauthz` verifies that all owner, foreign and
  anonymous observations carry the expected fingerprint.
- `bunnyfix.CompareBuildBound` checks both signed artifact measurements,
  requires distinct file digests and run IDs, and requires every signed
  HTTP receipt to carry the corresponding hash.
- `compare_build_bound_fix` is a new offline, verification-only agent tool
  that requires the existing BunnyGuard engagement manifest and pinned
  recorder public key.

## Recorder CLI

In the separate isolated recorder environment:

```sh
go run ./cmd/bunnybuild-attest \
  -artifact /absolute/path/to/local-test-build.bin \
  -private /isolated/private-ed25519.key \
  -output /isolated/build-evidence.json \
  -engagement local_lab \
  -run before_run
```

Use the same process for an after-run measurement with a distinct run ID
and artifact. The CLI does not contact the server or execute the file.
The private key must remain outside Antares's accessible environment.
Windows users should protect the key with an isolated account and NTFS ACLs.

## Trust boundary

**Artifact measurement is not deployment attestation.** The recorder signs
which local file it measured. It does not establish that the server
answering localhost requests actually executed that file, that the file
has an approved provenance, or that a real application was updated.

The result explicitly reports
`artifact_measurements_authenticated: true` and
`deployment_identity_verified: false` rather than implying a
production fix was confirmed.

An eventual production-grade verifier needs trusted deployment
attestations, isolated test accounts, pinned environments and repeated
regression tests across known application versions.

## Regression tests

```sh
go test ./internal/bunnybuild ./internal/bunnyreceipt \
  ./internal/bunnylab ./internal/bunnyauthz ./internal/bunnyfix ./internal/tools
```

The tests use temporary local files, ephemeral Ed25519 keys and synthetic
numeric-loopback HTTP fixtures. No real target is scanned.
