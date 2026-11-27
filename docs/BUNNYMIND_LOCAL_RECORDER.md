# BunnyMind v0.11 — local HTTP capture and signed receipts

This milestone provides a complete **synthetic/local training path** from
a real HTTP response to an Ed25519-signed evidence bundle. Unlike the v0.9
standalone `sign` command, v0.11 derives the status, response digest and
marker-present flag from **HTTP traffic it actually captures**.

## Security boundary

`bunnylab-recorder` accepts **only** explicit HTTP(S) numeric loopback
origins such as `http://127.0.0.1:8765` (or `http://[::1]:8765`).
Hostnames, DNS, external addresses, metadata networks and other private
network ranges are all refused. No redirects are followed, and redirect
responses are rejected. Only GET requests are permitted, with no request
bodies, cookies or custom auth headers. Each probe has an 8-second timeout
and at most 64 KiB of response bytes. A plan contains 4–32 probes and at
least two positive and two negative-control labels.

The recorder computes response digests and whether the response contains the
configured marker. It derives the marker-in-request flag from the requested
path and its decoded form. It **does not return response bodies**: only the
signed observation metadata, digests and signatures are saved.

The `positive`/`control` classifications and marker are supplied by the
test operator. A model can still choose misleading classifications. The
recorder does not independently establish what a negative control ought to
mean, whether a finding is exploitable, or its security impact.

## Runnable demonstration

Create a signing key outside any Antares or shared agent workspace:

```sh
go run ./cmd/bunnyreceipt-recorder -action keygen \
  -private /isolated-recorder/private.key \
  -public /isolated-recorder/public.key
```

Start a synthetic fixture from a separate terminal:

```sh
go run ./cmd/bunnylab-fixture -port 8765
```

Use the bundled `benchmarks/bunnylab/loopback-plan.json` (or an equivalent
plan with absolute paths on your machine), then:

```sh
go run ./cmd/bunnylab-recorder \
  -plan /absolute/path/to/loopback-plan.json \
  -private /isolated-recorder/private.key \
  -output /isolated-recorder/loopback-bundle.json
```

The output bundle is compatible with the v0.9 `verify_lab_receipts` tool
when its public key and BunnyGuard engagement ID match.

### Windows note

Create paths in PowerShell as appropriate, with absolute Windows-style paths.
Protect the signing key using a separate Windows account or VM and proper NTFS
access-control lists. Go file permissions alone do **not** establish adequate
Windows key isolation.

## Tests and limitations

```sh
go test ./internal/bunnylab ./internal/bunnyreceipt ./cmd/bunnylab-recorder ./cmd/bunnylab-fixture
```

Tests use ephemeral `httptest` servers on loopback. They verify signed
positive/control observations, redirect refusal, external-origin rejection,
response-size caps, duplicate-ID rejection and reflection handling.

**This is an isolated laboratory recorder, not an autonomous agent
penetration-testing benchmark.** It makes HTTP calls against a locally run
synthetic fixture only, not against bug bounty hosts. A signer compromise
or incorrectly instrumented fixture can still produce misleading receipts.
Later milestones must integrate trustworthy source-to-runtime test cases,
independent repeatability and full network-layer containment.
