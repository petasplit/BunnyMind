# BunnyMind v0.14: signed local remediation checks

A proposed security fix should have evidence that the problematic behavior
stopped, not merely a claim that code was changed.

Version 0.14 adds an offline `compare_authz_fix_receipts` tool that
accepts two signed v0.12 local authorization-lab runs—before and after
a simulated fix—with different run IDs, the same engagement/case/path,
and the same synthetic evidence marker.

It checks every Ed25519 signature using the configured recorder public key,
validates owner access, anonymous controls, and foreign-persona responses
in both runs, and reports one of:

- `remediation_observed_in_lab`
- `regression_observed_in_lab`
- `unchanged_exposure_in_lab`
- `unchanged_denial_in_lab`
- `inconclusive`

A bad signature, changed case, mismatched engagement, repeated run ID or
altered evidence is rejected. Different numeric-loopback ports are allowed
to represent two isolated local test builds.

The tool does **not** send HTTP requests, read signing secrets, apply a patch
or change the status of a vulnerability in the Antares findings ledger.
Its results do not establish production remediation or prove that two
different test ports host the same application version.

The recorder and authorization test cases remain confined to numeric
loopback. CI uses deliberately synthetic fixtures; no third-party
website is scanned.

Validation:

```sh
go test ./internal/bunnyfix ./internal/bunnyauthz ./internal/tools
```

To progress beyond simulated tests, a future version must bind signed
receipts to immutable deployment hashes, independent test accounts,
operator-approved scope and a separately isolated recorder.

## Standalone demonstration

In the v0.14 development branch, run four synthetic scenarios:

```powershell
go run ./cmd/bunnyfix-demo -mode remediation -json
go run ./cmd/bunnyfix-demo -mode regression -json
go run ./cmd/bunnyfix-demo -mode persistent -json
go run ./cmd/bunnyfix-demo -mode denied -json
```

Each command starts two disposable localhost test applications,
generates fresh random synthetic user tokens, captures and signs owner /
foreign / anonymous observations for each, then compares the two outcomes.

The GitHub Windows build workflow also produces
`BunnyMind-fix-demo-windows-x64.exe` and its SHA-256 checksum. The
native Windows smoke job runs all four modes against the Windows binary
and validates both eight-sample signed bundles in each scenario.

The fixture and signing key run in the same demo process; these results
illustrate the evidence pipeline and do **not** provide independent
production remediation attestation.
