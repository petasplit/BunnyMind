# BunnyMind v0.25 — redacted browser traffic evidence

This milestone adds a privacy-preserving network observation channel to **both the existing synthetic browser lab and the new v0.24 approved external HTTPS browser mode**.

## Captured fields

After each completed workflow step, the trusted `chromeDriver` drains the Chromium DevTools network events and records a bounded set of metadata-only receipts:

- Actor alias and workflow step number.
- HTTP method and approved origin.
- SHA-256 of the method, origin and URL path (not the URL itself).
- HTTP status, or a failed/pending classification if no response was observed.
- SHA-256 of the metadata, bound to identity, step, status and outcome.

The recorder **does not emit** raw paths, query parameters, request bodies, response bodies, headers, cookies, bearer tokens, email addresses, or session secrets. If a CDP event references a URL outside the approved origin set, it is discarded. At most 256 metadata receipts are returned per workflow.

## Verification and interpretation

`internal/bunnybrowserflow/traffic_test.go` covers query-independent endpoint fingerprints, private-field redaction, status-bound metadata, out-of-scope filtering, receipt limits, and end-to-end attachment of receipts to an approved workflow using a deterministic browser test double.

These records are browser-observed metadata, **not independent signed proof of a vulnerability**. Network events may be incomplete when responses arrive after a drain. Results must be corroborated with controlled owner/peer/anonymous tests and the independent evidence-verification workflow; high/critical severity is never inferred from status codes alone.

## How to use

Run the v0.24 operator CLI or the preauthorized `approved_browser_auth` agent tool. Existing configured flows now include an optional `traffic` array in their result. No extra model-provided target URL or traffic arguments are accepted.

Local-only tests remain available to prevent regressions, but the recorder also operates under the externally approved HTTPS browser factory with the same scope policy, proxy and credential isolation.

## Limitations

This is deliberately an initial metadata recorder, not an unrestricted proxy or complete HAR archival system. It does not provide replay of raw HTTP requests, automated mutation of authenticated endpoints, CAPTCHA defeat, or exploitation. Browser-subprocess traffic and service workers not captured by the attached DevTools page require separate auditing and an OS-level egress sandbox for stronger isolation.
