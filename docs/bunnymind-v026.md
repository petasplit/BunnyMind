# BunnyMind v0.26 — adaptive authorized authentication and operator-owned IMAP

## New capabilities

External approved HTTPS sites no longer require operators to prewrite every field selector. The trusted adaptive runner inspects the live page and classifies visible email, username, password, password-confirmation, and one-time-code controls, along with signup navigation and submit actions. It generates temporary, limited selectors, not a dump of page text or input values.

An operator-defined mode (`login` or `signup`), entry path, test personas, expected authenticated success indicator, and approved scope are still mandatory. Each session uses its own browser profile and preconfigured keyring credentials. Unknown, ambiguous, or repeated pages produce a blocker. An observed CAPTCHA or passkey prompt requires a human to complete that step.

The adaptive runner uses the v0.24 HTTPS scope controls (strict BunnyGuard origins, explicit POST path allowlist, DNS-pinned local CONNECT proxy, request limits and pacing) and the v0.25 redacted traffic receipt recorder. Nothing in this milestone grants arbitrary target discovery or WAF bypass.

The discovered-link navigator can also find a same-origin sign-in or registration link on a landing page and visit its validated path. When an authenticated run succeeds, BunnyMind derives up to eight evidence-linked `next_checks` (authorization controls, session lifecycle, state-changing endpoints, redirects, errors or transport recovery). If the current session has no investigation board, it seeds a **review-only** board with those tasks. It never overwrites an existing board or executes exploit requests based on the generated labels.

## Real mailbox verification

The optional IMAP adapter connects over verified TLS on port 993 to the operator-configured mailbox hostname. It validates all resolved addresses against private, loopback and special-use ranges, dials a checked IP, and verifies the expected TLS server name.

Before signup starts it records the inbox's next IMAP UID and a timestamp. During verification it reads only a small recent-message window, requires a new UID, checks the configured sender and the test-account recipient, and accepts only a single 6–8 digit verification code. If there is no trustworthy matching code or multiple matches, the workflow stops rather than guessing. Mailbox user, password, account email and account password are stored under the test persona in the OS keyring. Raw codes and messages are never emitted as tool output.

## Configuration (operator authored)

Continue to use `guard.json` and `scope.json` as defined in the v0.24 guide. Set scope `approved_post_paths` to the exact legitimate registration/login/verification endpoint paths permitted by the target's published testing rules.

Example `adaptive.json`:

```json
{
  "origin": "https://staging.example",
  "start_path": "/login",
  "mode": "signup",
  "actors": ["owner", "peer"],
  "success_text": "Your dashboard",
  "use_email_otp": true,
  "mailboxes": {
    "owner": {"host":"imap.example.com","sender":"verify@staging.example"},
    "peer": {"host":"imap.example.com","sender":"verify@staging.example"}
  }
}
```

This is an illustrative configuration. None of these example hosts has been contacted or verified.

Store each identity's operator-owned secrets interactively:

```powershell
go run ./cmd/bunny-approved-auth --set-secret owner:email
go run ./cmd/bunny-approved-auth --set-secret owner:password
go run ./cmd/bunny-approved-auth --set-secret owner:imap_user
go run ./cmd/bunny-approved-auth --set-secret owner:imap_password
go run ./cmd/bunny-approved-auth --set-secret peer:email
go run ./cmd/bunny-approved-auth --set-secret peer:password
go run ./cmd/bunny-approved-auth --set-secret peer:imap_user
go run ./cmd/bunny-approved-auth --set-secret peer:imap_password
```

Run using a visible browser for operator handoffs:

```powershell
go run ./cmd/bunny-approved-auth --guard guard.json --scope scope.json --adaptive adaptive.json
```

The agent-facing `approved_browser_auth` tool also supports the operator-configured environment variable `BUNNY_ADAPTIVE_AUTH_CONFIG` instead of `BUNNY_APPROVED_BROWSER_PLAN`. It still accepts **no model-supplied target URL, credentials or override plan**.

## Safety and performance limitations

- HTML form classification and deterministic state changes can fail on multi-step SPAs, shadow DOM, iframes or unusual signup forms. These become review blockers.
- The success text is operator-provided and a browser observation; it does not prove target authorization, account entitlement or vulnerability severity.
- The IMAP adapter is authorized to inspect only the configured operator mailbox. It cannot access unrelated inboxes, bypass MFA, or read arbitrary email attachments.
- The HTTP request budget applies to the browser gate. The IMAP client is a separate explicitly configured mailbox connection, not a generic network capability.
- Unknown account registration obligations (terms, payments, SMS verification, CAPTCHA) are not silently accepted. The operator remains responsible for complying with the engagement scope.
- A green GitHub CI is not evidence of successful authentication to a real external program; no live third-party target is used by CI.

## Validation

Unit and integration tests cover two-account adaptive login, signup-to-OTP navigation, duplicate/ambiguous control rejection, scope preflight, strict mailbox metadata checks and code freshness, with the preexisting Chromium and Windows smoke suites. Review PR CI before merging.
