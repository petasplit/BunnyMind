# BunnyMind v0.26 — Adaptive authentication discovery and trusted IMAP verification

This release extends the **externally scoped Chromium browser architecture** from v0.24–v0.25. No localhost-only limitation is imposed on the new runtime: it works with real, approved HTTPS application origins through the existing DNS/IP-pinned proxy and CDP request gate. Its tests remain isolated fixtures.

## What is implemented

### Structured authentication discovery

`internal/bunnybrowserflow/discovery.go` inspects the real DOM in the attached Chromium page and returns only a bounded classification of recognized inputs (`email`, `username`, `password`, `confirm_password`, `otp`), recognized actions (`login`, `signup`, `verify`), safe in-origin authentication links, and challenge/signed-in indicators. **Raw page text, input values, cookies, emails, DOM HTML and session tokens are never included in the returned snapshot.**

The discovery engine derives CSS selectors only from syntactically safe IDs or structural `nth-of-type` paths. Form inspection is bounded, and selector structures are validated again before use by the trusted browser integration.

### Bounded state-driven login and signup

`internal/bunnybrowserflow/adaptive.go` implements one test identity at a time, with a maximum of 12 observed transitions. `adaptive_batch.go` supports up to four isolated operator-defined test identities within an aggregate BunnyGuard request budget. Actions are selected from observed authentication state: first locate an in-origin login/signup link, then fill recognized fields, submit the permitted form action, inspect verification prompts, obtain the trusted code, and stop on a signed-in indicator, an explicit blocker, or an ambiguous page.

The controller does not repeatedly retry rejected credentials, invent network destinations, spray parameters, bypass CAPTCHA, or treat a 2xx response as proof of successful login. The external browser gate allows POST only on the operator's explicit endpoint allowlist; a newly discovered form never expands that allowlist.

### Dedicated real test mailbox via IMAP

`internal/bunnybrowserflow/mailbox.go` supports real dedicated test mailboxes using IMAP over TLS 993, with each test persona mapped to a unique configured recipient address and expected verification sender. It retrieves only a bounded set of recent messages, extracts a single numeric verification code, and checks sender, recipient, request-time freshness, and message UID to prevent stale or repeated use. It does not expose the email or code to the AI; only the trusted browser executor receives the code. The mailbox password is retrieved from the operating-system credential store.

The IMAP connector validates public DNS addresses, disallows private/loopback/metadata destinations, pins the resolved address and verifies the TLS hostname. Sender/recipient headers are not cryptographic proof of email authenticity, so this adapter must be used with operator-controlled test mailboxes and trusted expected senders. Codes must be associated with the account that requested them.

## Example operator configuration

The previously implemented `guard.json` and `scope.json` are still required, with exact approved HTTPS origins and permitted POST endpoint paths.

Adaptive configuration `adaptive.json`:

```json
{
  "actors": ["owner", "peer"],
  "mode": "signup",
  "entry_path": "/"
}
```

Dedicated mailbox configuration `mailbox.json`:

```json
{
  "host": "imap.example-mail-provider.com",
  "port": 993,
  "boxes": {
    "owner": {"address": "owner-test@example-mail-provider.com", "sender": "verify@app.example"},
    "peer": {"address": "peer-test@example-mail-provider.com", "sender": "verify@app.example"}
  }
}
```

All domains and mail addresses above are placeholders. The `email` stored for each persona must match its dedicated mailbox address. Only operator-provisioned test accounts should be used.

Provision credentials interactively to the OS credential store (the terminal does not echo values):

```powershell
go run ./cmd/bunny-approved-auth --set-secret owner:email
go run ./cmd/bunny-approved-auth --set-secret owner:password
go run ./cmd/bunny-approved-auth --set-secret owner:imap_password
go run ./cmd/bunny-approved-auth --set-secret peer:email
go run ./cmd/bunny-approved-auth --set-secret peer:password
go run ./cmd/bunny-approved-auth --set-secret peer:imap_password
```

Run against approved HTTPS staging or bug-bounty origins:

```powershell
go run ./cmd/bunny-approved-auth --guard guard.json --scope scope.json --adaptive-config adaptive.json --mailbox mailbox.json
```

`--headless` may be used for flows without interactive challenges. Real MFA, passkey and anti-bot challenges require operator action; they are not solved or bypassed by the agent.

## Agent integration

Before launching BunnyMind, configure the operator-controlled environment paths:

```powershell
$env:ANTARES_BUNNY_GUARD_POLICY = "C:\Audits\guard.json"
$env:BUNNY_APPROVED_BROWSER_SCOPE = "C:\Audits\scope.json"
$env:BUNNY_APPROVED_ADAPTIVE_CONFIG = "C:\Audits\adaptive.json"
$env:BUNNY_APPROVED_MAILBOX_CONFIG = "C:\Audits\mailbox.json"
```

The security agent can then invoke `approved_adaptive_auth` **with no arguments**. The tool ignores arbitrary model targets and obtains its actual authorization, personas, sign-in mode and mailbox configuration only from the trusted files. It records sanitized result digests in the v0.21 exploration timeline.

## Tests and limitations

Unit tests cover form classification, selector safety, unknown forms, multi-persona budgets, trusted IMAP configuration and sender/recipient/time/UID OTP filtering, consumed-code replay rejection, restricted authentication steps, and no-secret output. CI continues to exercise the established Chrome/Windows fixtures.

At this stage, dynamic discovery handles conventional visible forms and common redirects. Multi-step passwordless sign-in, OAuth popup flows, unconventional shadow DOM components, visual-only form controls, custom anti-bot challenges and account-creation policies still require manual or preapproved special-case adapters. A site's sign-in indicator remains a heuristic until confirmed with a controlled authenticated-resource check; the engine does not claim confirmed vulnerabilities or BugBunny performance parity.

**No external site or mailbox is accessed by the CI tests.** Actual provider setup and scope authorization must be configured on the operator's machine.
