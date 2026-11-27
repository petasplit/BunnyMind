# BunnyMind v0.5: scoped read-only HTTP transport

## What is implemented

The `scoped_read` agent tool issues one GET or HEAD request using a fresh
Go HTTP transport with **no proxy, no redirects, no cookies and no custom
headers**. It is an opt-in, approval-gated capability tied to the existing
BunnyGuard manifest.

Defense-in-depth checks:

1. An Antares agent preflight checks a model-selected request's declared
   origin, GET/HEAD method, rate interval and remaining model-tool budget.
2. The `scoped_read` tool re-reads and validates the engagement manifest.
3. The transport resolves DNS immediately before connecting and tests every
   returned IP. Private, loopback, link-local, multicast and unspecified
   addresses are blocked unless permitted through a **narrow CIDR** in the
   manifest or an exact IP literal in the allowed origin.
4. Connection goes to the validated IP, not a new resolver result.
5. HTTP redirects are not followed, including 307/308. The response records
   `redirect_blocked`; a follow-up request needs its own approved call.
6. Response reading is capped at 64 KiB; returning body preview is optional,
   0 by default. Request/response bodies aren't included in the policy audit.

Example manifest:
```json
{
  "engagement_id": "local-approval-lab",
  "allowed_origins": ["http://127.0.0.1:8765"],
  "allowed_methods": ["GET", "HEAD"],
  "allowed_cidrs": [],
  "max_network_calls": 40,
  "min_interval_ms": 200
}
```

For a hostname that intentionally resolves to a private IP on an isolated
owned test network, add the smallest appropriate CIDR under `allowed_cidrs`
(e.g. `127.0.0.1/32` for explicit localhost). An overly broad `/0`
exception is refused.

**Guarded-mode policy changed in v0.5:** legacy `http_request` and
`web_fetch` calls are denied. `scoped_read` is the only network tool
allowed by this particular engagement preflight. This is intentional because
the legacy fingerprinting client can follow redirects without the same
network-layer controls.

## What is NOT enforced

This is a scoped HTTP **reader**, not a complete network sandbox. It does not
control indirect traffic from background plugins, providers, MCP servers,
external browser processes, other processes, raw sockets or shell tools.
The agent tool is offline-disabled when the guard policy is absent, but
Antares's other tools are unchanged outside guarded mode. Platform-specific
container network policy is still recommended. These checks do not implement
authenticated state-changing web assessment or OAuth/login automation.

No outbound test calls are made in CI: the Go regression tests use local
`httptest` servers. Tests include cross-origin rejection, redirect refusal,
private-IP limitations, response limits, method restrictions and literal-IP
matching.

Run: `go test ./internal/bunnynet ./internal/bunnyguard ./internal/tools`.
