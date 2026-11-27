# BunnyMind v0.27 — SPA/SSO login, trusted magic links and owned MFA

## Architecture and scope

Builds on v0.26's **real approved HTTPS browser** integration, not a localhost-only implementation. Exact HTTPS application and identity-provider origins must already appear in the operator's BunnyGuard and browser-scope files. Network requests still flow through the DNS-pinned CONNECT proxy and page-scoped Chrome request gate. Normal and Full modes do not grant new network permissions.

### 1. Unusual single-page applications and IdP redirects

The semantic DOM scanner now traverses bounded open shadow roots and accessible same-origin iframes, recognizes forms inside them, and uses a temporary `data-bm-auth` reference table rather than replacing the application's element IDs. After clicking a form it waits for a real UI transition, asynchronous hydration, a page navigation, or an approved redirect instead of assuming that the DOM instantly changed.

Explicitly listed IdP origins can be recognized as an external 'Continue with / SSO' navigation. The browser clicks only a recognized link to an exact IdP origin already present in the mission's allowlist, then checks that the redirect/callback remains within approved origins. The OAuth `state`, authorization code and other URL query data are not returned by discovery or the evidence recorder.

**Limit:** This supports current-tab redirect-based SSO, including simple OIDC authorization-code callbacks. Providers that open separate popups or require native passkey/device prompts may still block; BunnyMind does not bypass them. Some closed shadow roots and cross-origin iframes remain inaccessible.

### 2. Magic-link authentication through an operator-owned mailbox

`use_magic_link` uses the existing strict IMAP TLS adapter and its fresh UID checkpoint. It requires a trusted configured sender, recipient and explicit HTTPS magic-link callback path prefixes. A link is accepted only when exactly one new verified email provides a URL to an authorized origin and approved callback path. It is opened in that persona's isolated browser. Raw link tokens are never put into a finding, telemetry event or assistant output. Multiple or off-scope links fail closed.

### 3. Automatic MFA for enrolled test accounts

`use_totp` calculates RFC 6238 SHA-1 6-digit TOTP codes from the operator-enrolled account's `totp_seed` stored in the OS keyring, honoring the 30-second step. This is legitimate second-factor completion for a test identity you control, not MFA bypass. Email OTP remains supported through `use_email_otp`. Choose exactly one of these three factor modes per adaptive configuration; separate runs can cover other flows.

Store the seed via the existing trusted local CLI:

```powershell
go run ./cmd/bunny-approved-auth --set-secret owner:totp_seed
```

### 4. Official CAPTCHA testing only

With `captcha_test_mode: true`, BunnyMind recognizes official public Cloudflare Turnstile or Google reCAPTCHA testing sitekeys. It can proceed without an operator **only when the page itself provides a legitimate test response**, and it never fabricates, injects or reuses a CAPTCHA token. Production challenges, unknown sitekeys, and real passkeys still need an authorized human action. Tests do not override site-level anti-bot protections.

Reference documents:

- https://developers.cloudflare.com/turnstile/troubleshooting/testing/
- https://developers.google.com/recaptcha/docs/faq/
- https://www.rfc-editor.org/rfc/rfc6238

## Example adaptive configuration

These domains are examples, not verified live services. In your `guard.json` and `scope.json`, declare exact staging and identity-provider origins and legitimate POST paths before running:

```json
{
  "origin": "https://staging.example",
  "start_path": "/login",
  "mode": "login",
  "actors": ["owner"],
  "success_text": "My test dashboard",
  "idp_origins": ["https://idp.example"],
  "use_totp": true,
  "captcha_test_mode": false
}
```

For email magic links, replace `use_totp` with:

```json
{
  "use_magic_link": true,
  "magic_link_prefixes": ["/auth/magic"],
  "mailboxes": {
    "owner": {"host": "imap.operator.example", "sender": "login@staging.example"}
  }
}
```

The example fragments show alternative fields, not a complete file to concatenate verbatim. Use a single factor type at a time.

Run with your existing operator-installed scope and profile:

```powershell
go run ./cmd/bunny-approved-auth --guard guard.json --scope scope.json --adaptive adaptive.json
```

## DorkixAI-inspired multi-target mission profiles

Public DorkixAI descriptions mention prioritized additional targets, Normal and Full assessment modes, selectable time budgets and interactive exploration of individual findings. BunnyMind v0.27 now exposes the analogous **operator-scoped planning and evidence-review capabilities**. No proprietary Dorkix source was available or copied.

Example `mission.json`:

```json
{
  "engagement_id": "approved-staging-assessment",
  "mode": "full",
  "time_budget_minutes": 240,
  "targets": [
    {"origin": "https://staging.example", "priority": 5},
    {"origin": "https://idp.example", "priority": 2}
  ]
}
```

Set `BUNNY_MISSION_PROFILE` to this local file and `ANTARES_BUNNY_GUARD_POLICY` to its matching manifest. The `engagement_profile` security tool accepts **no target arguments**; it produces an ordered offline plan with per-target time/request allocations. Every origin must already be authorized by BunnyGuard. The mode controls suggested methodology breadth, not attack permissions. The plan itself does **not** launch a scan or claim completion.

`finding_focus` supports `inspect`, `ask`, `retest`, and `remediation` against an existing `F-001`-style finding ID from the current engagement. It reports evidence gaps and independent review procedures without exposing stored raw PoC strings, credentials or affected URLs, and does not mark a model-supplied finding confirmed.

## Tests and known limits

Unit tests cover RFC 6238 reference vectors, exact Magic Link origin/path validation, sender/recipient/freshness and ambiguous-link rejection, bounded multi-target mission allocations, finding-level cross-session privacy and adaptive simulated IdP/TOTP/CAPTCHA flows. The dedicated Chrome job also tests actual shadow-DOM form discovery and scoped SSO-link detection, with secrets kept out of output.

Tests use controlled fixtures and modeled HTTP transitions; they do not prove live compatibility with Okta, Entra ID, Google sign-in or a named external bug-bounty target. Popup-only SSO, hardware keys, production CAPTCHA challenges and cross-origin iframe control remain unsupported for unattended completion. The browser transport and IMAP client are not OS sandboxes; run authorized assessments from an isolated machine/VM with independent egress rules.
