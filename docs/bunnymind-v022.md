# BunnyMind v0.22 — Cross-identity authorization matrix

This change improves a capability visible in the BugBunny screenshots: separate test accounts and replayable authentication evidence. It **does not** provide uncontrolled account registration or live-target exploitation.

## New agent tool: auth_access_matrix

The tool accepts up to 256 structured observations and analyzes up to 64 distinct authorization cases across **owner, peer and anonymous** test personas.

Each observation contains only a stable case/endpoint ID, opaque resource SHA-256, owner and acting test-persona IDs, HTTP method/status, a signal indicating whether a harmless pre-seeded test-resource marker was present, the marker's SHA-256 (only when present), an evidence digest, and caller-declared provenance.

The comparator requires:
- A **2xx owner baseline with the expected harmless test marker** before identifying cross-identity access.
- A peer or anonymous **2xx response containing the same marker** to flag a candidate. A 2xx response by itself is inconclusive.
- Two distinct owner and peer evidence digests and a denied anonymous control before labeling a candidate as repeatedly observed.
- A separate, independent, scope-approved reproduction before treating **any** result as confirmed.

Outcomes include:
- `owner_baseline_missing`
- `peer_control_missing`
- `peer_access_denied`
- `inconclusive`
- `cross_identity_candidate`
- `repeated_cross_identity_candidate`
- `anonymous_resource_access_candidate`

Each case reports missing controls and evidence requirements, not a fabricated vulnerability severity. Inputs are validated for safe IDs, digests, supported request types, bounded HTTP statuses, duplicate observations and consistent ownership.

For privacy and safety, the tool never accepts request headers, passwords, tokens, actual account emails, raw URLs or response bodies; its output contains only metadata. It requires an existing BunnyGuard engagement manifest and does not send any HTTP requests or create test accounts. Caller-supplied provenance labels remain **unattested**.

## End-to-end synthetic authentication example

The existing `auth_workflow_lab` / `bunnyauthflow.Run` runs two disposable synthetic registrations on numerical localhost, privately reads test email OTPs, exchanges them for isolated sessions, and checks owner, foreign and anonymous access. Its output now includes an `access_comparison` value computed by the **same** matrix engine from real test fixture HTTP observations.

Expected fixture outcomes:
- Correctly isolated fixture: `peer_access_denied`
- Deliberately weak fixture: `cross_identity_candidate`

The fixture remains bound to numeric loopback, and it does not expose raw OTPs, session tokens, mailbox messages or benign marker values.

## Activity and evidence integration

An actual matrix analysis performed with the agent tool records a redacted, tool-observed `evidence` timeline entry containing only an opaque report digest and a status. Candidate results are marked `needs_review`; non-candidate results are summarized as completed analysis. This does not assert independent verification.

## Running and reviewing

Go package tests:

    go test ./internal/bunnymatrix ./internal/bunnyauthflow ./internal/tools

Local end-to-end fixture:

    go run ./cmd/bunny-authflow-demo

Review the CI and Windows build results on the PR before merging it. Synthetic results and sanitized, operator-collected metadata are not a measurement of real-world penetration-testing effectiveness.

## What still needs building

- A trusted, explicitly authorized browser/registration adapter for user-owned staging domains, with session isolation and operator-handled MFA/anti-bot challenges.
- A graphical account/traffic explorer over the redacted evidence ledger.
- A benchmark that compares held-out real application tests against other autonomous tools, controlling false positives, coverage and request budgets.
