# BunnyMind v0.12: synthetic cross-persona authorization lab

The new `bunnyauthz` module checks whether two synthetic test accounts
receive appropriately different responses for a **single resource in an
isolated numeric-loopback application**.

The recorder submits three personas: `owner`, `foreign`, and
`anonymous`. Owner and foreign synthetic bearer tokens are held in a
private in-memory `Tokens` structure, never in the JSON plan or signed
observation. Tokens must be distinct; query strings and URL fragments in the
resource path are prohibited. The recorder rejects missing or malformed tokens *before sending requests*. The existing `bunnylab`
recorder still limits requests to GET on numeric loopback addresses, does
not follow redirects, and caps response data to 64 KiB.

Two four-observation bundles are created:

1. **Owner access**: two authenticated owner responses plus two anonymous
   negative controls.
2. **Cross-user access**: two foreign-user responses for the same resource
   plus two anonymous controls.

Each observation is signed with a separate recorder key. The added
`Actor` field is included in the signature; observations without actors
remain compatible with the v0.9 schema.

The `assess_authz_receipts` agent tool does **not** access any bearer
tokens or send HTTP requests. It validates both bundles with the pinned
recorder public key and the BunnyGuard engagement ID.

## Possible outcomes

- `cross_persona_marker_observed_in_lab`: the owner and foreign synthetic
  accounts both received the selected protected marker, while anonymous
  controls were denied.
- `cross_persona_denied_in_lab`: the legitimate owner received the marker
  while both the foreign user and anonymous controls were denied.
- `inconclusive`: owner access failed, signatures did not establish
  consistent observations, or the expected comparisons were not met.

**This is a lab behavioral comparison, not a confirmed IDOR/BOLA finding**.
A vulnerable fixture must be deliberately configured to simulate access
control failure; production authorization depends on actual identity,
ownership and business rules.

## Run and validate

```shell
go test ./internal/bunnyauthz ./internal/bunnylab ./internal/bunnyreceipt ./internal/tools
```

The tests use ephemeral `httptest` servers. One intentionally vulnerable
fixture returns a protected synthetic marker to the foreign test account;
a control fixture denies it. The tests ensure owner/anonymous comparisons,
repeatability, signature verification, cross-run rejection and removal
of bearer tokens from evidence outputs.

## Limits and next steps

This module is exercised through Go tests. There is not yet a production
browser account-creation or multi-account login workflow. Credential
injection is available **only to the separate loopback recorder**, not to
the Antares agent tool. The private signing key must remain outside
agent-accessible environments; a separate OS user/VM is appropriate.

A next milestone can introduce an opt-in trusted recorder service for
user-owned staging environments, allowlisted through an actual egress
boundary, with explicit operator authorization and test-account isolation.
Do not reuse this test-only code for live third-party sites without that
containment and independent review.


## Runnable demonstration (Windows / Linux / macOS)

The fork also contains a standalone demonstration command:

```sh
go run ./cmd/bunnyauthz-demo
```

This starts a disposable `httptest` server bound to numeric loopback,
uses two fixed **synthetic** identities, and reports
`cross_persona_denied_in_lab` for the secure fixture. To demonstrate a
controlled simulated authorization failure:

```sh
go run ./cmd/bunnyauthz-demo -vulnerable
```

The expected result is `cross_persona_marker_observed_in_lab`. Both
modes compute actual HTTP response digests and Ed25519 receipts, then
verify those signatures and evaluate owner/foreign/anonymous controls.
No raw account token or response body is printed.

The demo signer and fixture intentionally run in the **same process**,
so the result is only a reproducible example, not independent attestation.
Only the separate recorder with an isolated key can eventually support
stronger provenance guarantees.

The GitHub Windows x64 workflow compiles the standalone demo executable
alongside the main BunnyMind build and makes it available as a CI artifact.
