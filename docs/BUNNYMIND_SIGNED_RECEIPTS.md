# BunnyMind v0.9 — Signed Evidence Receipts

The v0.2 `review_evidence` tool compares user/model-supplied observations but
cannot distinguish fabricated data from trustworthy test-lab results.

v0.9 introduces `bunnyreceipt`: **Ed25519 signatures on small, structured,
offline observations**. A dedicated and separately operated test-lab recorder
keeps the Ed25519 signing private key; the Antares `verify_lab_receipts`
agent tool receives **only the public key** through
`BUNNYMIND_RECEIPT_PUBLIC_KEY_FILE`, a trusted absolute path.

## Security properties

- Each signed observation binds the engagement ID, run ID, case ID, unique
  sample ID, positive/control role, method, HTTP origin, response status,
  request and response SHA-256, marker SHA-256, marker presence/reflection
  flags, and timestamp.
- Signatures must verify against the pinned public key. Tampering with a
  signed observation, submitting a signature from another recorder, mixing
  engagements/runs/cases, reusing sample IDs or mixing indicator hashes and
  origins makes the bundle fail.
- A consistent result requires at least two signed positives and two
  signed negative controls, with positive marker assertions and no indicator
  reflection. Contradictions return `inconclusive`.
- The tool returns receipt digests and a short conclusion; it never emits
  raw HTTP requests, response bodies, credentials, a private signing key
  or an arbitrary URL.
- Verification requires a valid BunnyGuard engagement manifest. The tool's
  input cannot select another engagement.

## Trusted recorder setup

The standalone `cmd/bunnyreceipt-recorder` utility is **not** an agent tool.
Run it in a separate, isolated owned/staging test environment. It generates a
key pair and signs one pre-existing structured observation per invocation.
The CLI cannot perform network requests, scans or PoC execution.

### Example

```sh
go run ./cmd/bunnyreceipt-recorder -action keygen \
  -private /isolated/recorder/private.key \
  -public /path/to/bunnymind/public.key
go run ./cmd/bunnyreceipt-recorder -action sign \
  -private /isolated/recorder/private.key \
  -input /isolated/recorder/observation.json \
  -output /isolated/recorder/receipt.json
```

**Do not place the private key under ANTARES_HOME, the workspace, Git, CI
secrets, an MCP tool, or any path the agent can access.** Running the recorder
and the agent under the same unrestricted OS account would defeat that
isolation. Use separate users/containers/VMs and an allowlisted public-key
handoff. The recorded marker flags are assertions by the signer; a compromised
or misconfigured signer can still attest false observations.

On Windows, protect the key using suitable NTFS ACLs; Go file modes alone
are not a substitute for Windows ACL isolation.

### Agent-side configuration

```sh
ANTARES_BUNNY_GUARD_POLICY=/absolute/approved-engagement.json
BUNNYMIND_RECEIPT_PUBLIC_KEY_FILE=/absolute/pinned-public.key
```

Pass a `bundle` of signed receipts with matching engagement/run/case IDs to
`verify_lab_receipts`.

## Limitations

**`consistent-signed-observations` is not an exploit verification label.**
Signatures authenticate a recorder that has access to the private key, not
the truth of its observations. The current receipt format is not a
transparency log, lacks external timestamp authority and revocation, and
does not independently replay requests or validate business impact.

These receipts can eventually be linked to BunnyHarness and BunnyBench,
but v0.9 does not automatically promote findings into reports.

## Tests

```sh
go test ./internal/bunnyreceipt ./internal/tools ./cmd/bunnyreceipt-recorder
```

Tests use synthetic records and ephemeral signing keys, never real targets.
