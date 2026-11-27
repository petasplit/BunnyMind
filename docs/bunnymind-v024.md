# BunnyMind v0.24 — approved external HTTPS browser sessions

BunnyMind now supports **operator-approved external HTTPS applications**, not only localhost fixtures. The new adapter executes an operator-authored sequence through real Chromium with separate profiles for each test-account persona. The site and network permissions must be independently declared in a BunnyGuard manifest; no URL or credentials are obtained from a model response.

## External network architecture

- `internal/bunnyegress`: a local HTTP CONNECT-only proxy bound to `127.0.0.1`, with exact HTTPS host/port allowlists, DNS answer validation, direct dialing of validated public IP addresses and a tunnel limit. It does not follow redirects or resolve target hosts by re-dialing an unvalidated hostname. Non-CONNECT traffic is denied, as are private/loopback/link-local/metadata/special-use addresses.
- `internal/browser/external_guard.go`: a second CDP `Fetch.requestPaused` check on each page request. Only exact HTTPS origins, GET/HEAD/OPTIONS, and POST to explicitly approved endpoint paths are permitted. Browser-level request counts and minimum spacing apply.
- `internal/bunnybrowserflow`: the existing typed authentication flow now supports external origins, multiple isolated test identities, trusted secret refs, and operator handoff for MFA/passkeys/anti-bot checks. Scope must be a subset of the BunnyGuard manifest, including `POST` permission and a total request budget across the planned identities.
- `cmd/bunny-approved-auth`: a local operator CLI that loads a validated scope and workflow from JSON, reads test-account secrets from the operating system keyring, and launches the approved browser without exposing credentials to agent tools.

The proxy is a defense-in-depth network constraint; Chrome CDP alone is not a general security sandbox. The proxy pins every CONNECT to checked public IP addresses, including rejecting mixed safe/private DNS responses. Keep the application isolated on a trusted machine. Browser/OS processes may have traffic outside the intercepted page and OS-level network controls are recommended for stricter environments.

## Example trusted configuration

Example BunnyGuard authorization manifest (`guard.json`):

```json
{
  "engagement_id": "approved-staging-assessment",
  "allowed_origins": ["https://staging.example"],
  "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST"],
  "max_network_calls": 150,
  "min_interval_ms": 200
}
```

Example browser scope (`scope.json`):

```json
{
  "engagement_id": "approved-staging-assessment",
  "allowed_origins": ["https://staging.example"],
  "approved_post_paths": ["/login", "/register", "/verify"],
  "max_browser_requests": 50,
  "max_tunnels": 8,
  "min_interval_ms": 250
}
```

Example operator-written workflow (`plan.json`):

```json
{
  "origin": "https://staging.example",
  "steps": [
    {"actor":"owner","op":"navigate","path":"/login"},
    {"actor":"owner","op":"fill_secret","selector":"#email","secret_key":"email"},
    {"actor":"owner","op":"fill_secret","selector":"#password","secret_key":"password"},
    {"actor":"owner","op":"click","selector":"#submit"},
    {"actor":"owner","op":"assert_text","expected_text":"My account"}
  ]
}
```

These `example` domains are placeholders, not tested endpoints. Replace them only with origins explicitly authorized by the operator and the actual engagement rules. Exact selectors and POST paths must reflect the approved application; unauthorized paths remain blocked. For external sign-in methods involving SSO, include every permitted identity-provider HTTPS origin in both manifests and the browser scope. Login steps are operator-authored, not dynamically scraped or inferred in v0.24.

## Windows and other supported systems

Store test-account values interactively in the OS credential store, without writing them into the plan:

```powershell
go run ./cmd/bunny-approved-auth --set-secret owner:email
go run ./cmd/bunny-approved-auth --set-secret owner:password
```

Run a configured assessment:

```powershell
go run ./cmd/bunny-approved-auth --guard guard.json --scope scope.json --plan plan.json
```

Add `--headless` for flows without interactive challenges. In visible-browser mode, an `operator_handoff` step pauses for the human to resolve MFA, passkeys or anti-bot verification in the open browser, then requires an explicit local acknowledgement. No CAPTCHA, MFA, or anti-bot bypass is implemented. A one-time code may be stored as a trusted secret ref for a time-limited run, but the AI never reads or stores the raw code.

## Current limits and risks

- Only HTTPS origins on TCP port 443 are supported externally. On-prem, IP-private, localhost and non-default HTTPS ports remain blocked by the external proxy. The independent local lab still supports loopback fixtures.
- HTTP request budgets are bounded per run and per identity; the operator must ensure repeated runs across a shared engagement do not exceed program-wide limits. The existing BunnyGuard journal is **not** automatically charged for each externally proxied browser request; it is a separate approval control. Future work should unify these ledgers.
- Browser credential secrets are in the OS keyring and must never be committed. Do not store third-party users' credentials or inspect their account data. The flow is designed for explicitly provisioned test accounts.
- A pass for this code in GitHub CI does not prove that any particular external site accepted login or that a vulnerability was found. No external site is scanned as part of CI.
- Browser background services, WebSockets, popups, and service workers require additional sandbox hardening if adversarial pages are in scope; run from an isolated VM with egress rules when necessary. The browser intercepts requests in its attached tab, while the DNS-pinned proxy independently restricts outgoing HTTPS tunnels.
- The current runner uses operator-authored scripts and does not infer or automatically adapt a target site's authentication fields. It has no arbitrary payload generation or WAF evasion.

## Validation

Package tests include proxy DNS pinning and special-IP denial, CONNECT-only behavior, browser request and method allowlists, rate limits, strict engagement configuration, two-persona budget checks, and no-secret evidence results. Review the related PR's GitHub Actions statuses before merging.

The next extension is a trusted session-evidence recorder over this transport, followed by a scoped and reviewable browser workflow designer. Those additions should preserve the independent egress and account-isolation boundaries.
