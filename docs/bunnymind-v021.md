# BunnyMind v0.21 — Exploration timeline and local HAR context

This milestone implements two observable workflow capabilities from the BugBunny screenshots without reproducing or claiming knowledge of its proprietary internals.

## Durable exploration timeline

The security tool exploration_timeline can append an agent-declared event, read a filtered page, and return a summary. Every event has a session-local sequence, lane, action, state, optional parent sequence, task ID, asset ID and SHA-256 evidence reference. Entries persist as owner-only JSONL with predecessor hashes and verification on replay. Invalid entries or a broken chain prevent future appends. Up to 10,000 entries are accepted per session.

Successful scoped_read GET/HEAD calls automatically record tool-observed HTTP metadata: origin, opaque URL fingerprint, method, status, body digest, byte count and truncation flag. No credentials, raw URLs, query parameters, headers, cookies, or bodies are recorded in the timeline.

The distinction matters: agent_declared "succeeded" means an agent assertion; tool_observed means a specific local tool executed successfully. Neither is independent proof of a vulnerability. The hash chain is tamper-evident but not a signed independent attestation, and this journal is intended for a single writer process.

## Local HAR metadata inventory

The security tool har_context_inventory accepts only a relative HAR path within the current workspace, verified after symlink resolution, and requires an existing BunnyGuard engagement policy. The importer makes no network requests.

The parser reads at most 8 MiB and 10,000 exchanges, filters exact approved origins, counts in-scope/out-of-scope/invalid requests, and summarizes method, status class, authentication-context presence and unique endpoints. Endpoint names are opaque method+origin+path hashes (maximum 200 shown). Raw requests, URLs, credentials, header values, response data and query strings are not returned or persisted. A successful local import creates a tool-observed exploration entry; the HAR itself is caller-supplied context, not attested fresh traffic.

## Suggested tool flow

1. Run scoped_read after an explicit allowed-origin engagement policy is validated.
2. If a user has supplied a HAR capture, inspect it with har_context_inventory using a workspace-relative .har filename.
3. Record observed assets via inventory_graph and plan work with investigation_board.
4. Link agent decisions and retest branches with exploration_timeline.
5. Read the timeline and differentiate tool-observed events from agent declarations before reporting.

## Verification and limits

Unit tests cover replay, corrupt-record rejection, session isolation, concurrent writes, method and scope filtering, and HAR secret redaction. GitHub Actions reports the actual pass/fail outcome.

Still not implemented: live third-party registration and OTP integration, approved target session replay, graphical traffic browser, cross-process locking, independent signed journal receipts, or a controlled BugBunny-equivalent effectiveness benchmark. CAPTCHA/MFA bypass is not included. The existing authentication fixture is localhost-only, not a live-target sign-in adapter.

This milestone adds observability and importable authentication context without changing approved active network permissions.
