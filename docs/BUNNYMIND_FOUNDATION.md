# BunnyMind: Antares fork foundation

Based on [enowdev/antares](https://github.com/enowdev/antares), Apache-2.0.
LICENSE and NOTICE are retained. This is an early development branch, **not**
a validated autonomous vulnerability-discovery product.

## Integrated in this pull request

- Opt-in engagement preflight on model-selected calls after plugin argument rewrites.
- Explicit HTTP(S) origin and method allowance for http_request and web_fetch.
- Request budget, optional minimum interval and redacted audit hash chain.
- The guarded mode denies shell, browser, crawler, MCP and unrecognized tools.
- Fresh-install defaults changed to manual approvals, auto sandbox selection
  and disabled shell network access. Existing user configuration may override.

Set ANTARES_BUNNY_GUARD_POLICY to the absolute path to a JSON manifest,
for example:

```json
{
  "engagement_id": "local-training",
  "allowed_origins": ["http://127.0.0.1:8765"],
  "allowed_methods": ["GET", "HEAD"],
  "max_network_calls": 100,
  "min_interval_ms": 200,
  "audit_path": "bunnyguard-audit.jsonl"
}
```

Run go test ./internal/bunnyguard ./internal/agent ./internal/config

## Known limitations

This guard is NOT a security boundary for the browser, direct shell egress,
HTTP redirects, DNS changes, plugin side effects, background code or external
MCP servers. The audit hash chain is not signed, so a privileged actor could
rewrite it. Native Windows sandbox auto mode does not provide a strong jail.
Use a VM/container with restricted networking. Do not use this milestone for
unattended third-party security tests.

## Next engineering milestones

1. All-request egress proxy with redirect/DNS/WebSocket enforcement.
2. Reproducible sanitized evidence and negative-control validation.
3. Isolated, permissioned test accounts and authenticated session separation.
4. Durable bounded work queues and independent result reviewers.
5. Repeated controlled benchmarks with local inference and false-positive scoring.
6. Reproducible Windows build and dependency-hardening workflow.
