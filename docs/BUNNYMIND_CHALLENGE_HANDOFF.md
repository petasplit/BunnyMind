# BunnyMind v0.19 — authentication challenge broker

The authentication layer needs a reliable way to distinguish **email
verification that an authorized test harness can complete** from MFA,
passkey and anti-bot challenges that require a trusted human operator.

The new `bunnychallenge` package is a bounded **in-process challenge state
machine**, not an anti-bot bypass system.

## Challenge types

- `email_otp`: `pending_trusted_otp` → completed by the trusted inbox
  adapter after a successful OTP exchange. A successful session token's
  high-entropy digest is recorded, **never the OTP itself**.
- `totp`, `passkey`, `push_mfa`, `anti_bot`: immediately enter
  `pending_operator`. The agent cannot complete them. A separate operator
  must sign an explicit approve/reject decision with a configured Ed25519
  private key held outside the agent.
- Expired or rejected tickets cannot be reopened or silently retried.

Every ticket has a randomly generated opaque ID, short actor alias,
15-second to 10-minute lease, at most three failed email attempts, and
a bounded total ticket budget of 32. The broker returns only state and
safe metadata; it never holds the OTP, recovery codes, cookies, password,
private signing key or an anti-bot challenge solution.

## Operator authorization

The trusted *operator* code—not an agent tool—can use
`bunnychallenge.SignDecision(private, ticketID, decision, timestamp)`
to produce a signed decision record. The broker accepts it only when:

- The signer matches the explicitly configured Ed25519 operator public key.
- Ticket ID, decision and timestamp are bound to the signature.
- The ticket belongs to a human-controlled challenge, remains pending
  and is inside its expiry period.
- The ticket has not been previously approved/rejected.

This **does not implement** clicking a CAPTCHA, bypassing Turnstile,
answering personal MFA challenges, or compromising login protections.
The operator must perform an authorized action on the original provider
through permitted UI/API methods before approving the ticket.

The model-facing `auth_workflow_lab` remains restricted to local
synthetic accounts. This release has **no externally accessible operator
approval endpoint** and no cross-process persistence. A future staging
adapter will require an operator UI, authenticated request/response
binding, scoped identity grants, and protected key custody.

## In-process integration

v0.19 wires the challenge broker into the existing
`bunnyauthflow.Coordinator`. It opens an email challenge before synthetic
account registration and requires settlement after the real local OTP
exchange succeeds. The in-memory session vault is updated only after
the trusted flow returns an actual session grant.

This still does not provide independently signed real-world account
creation. It ensures local workflow state and OTP policy cannot be
mistaken for automated MFA or WAF bypass.

## Tests

```sh
go test ./internal/bunnychallenge ./internal/bunnyauthflow ./internal/bunnyidentity
```

Tests cover challenge expiry, failed attempts, replay, operator-signature
verification, wrong-signer denial, absence of operator authority,
cross-ticket approval reuse, secret-redacted status and ticket quotas.
