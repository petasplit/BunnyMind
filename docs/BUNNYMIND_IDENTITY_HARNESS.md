# BunnyMind v0.18 — Trusted authentication adapters and session vault

This milestone turns the v0.16 disposable test registration into a
**pluggable internal authentication workflow**. Rather than return test
bearer tokens to an agent, enrollment now uses trusted interface ports
and an in-process, actor-scoped credential vault.

## Implemented

- `RegistrationPort` has narrow operations `Register` and
  `ExchangeEmailCode`, without raw target URLs or arbitrary HTTP options.
- `InboxPort` only yields the expected test-account verification message.
  The coordinator checks sender and recipient and extracts one six-digit OTP.
- `Coordinator.Provision` creates the synthetic test account, consumes its
  email OTP, and stores the resulting bearer session in a private `Vault`.
  It returns only an actor alias, resource reference and boolean status.
- `LocalRegistrationPort` is the sole implemented adapter. It uses the
  existing numeric-loopback client and `example.test` synthetic identities,
  never outside websites or real mailboxes.
- `bunnyidentity.Vault` has a maximum of eight active actor aliases,
  explicit 15-second to 30-minute leases, guarded rotate/revoke/close
  methods and redacted session views.
- `Run`, used by the agent's `auth_workflow_lab` and the Windows demo,
  is now wired through the coordinator and vault. Owner/foreign/anonymous
  comparison, a new OTP login, token rotation, replay and logout are
  checked using isolated session callbacks.

## Credential boundaries

The vault is **in memory only**; it is not serialized or persisted by the
agent. Session callbacks supply the bearer token only to trusted local
transport code, not to the model or the final tool result. On rotation
or revocation, the vault wipes its internal token-byte buffers.

These are application-level controls, **not a hardware-backed secret vault**.
Go strings used temporarily by HTTP libraries cannot be guaranteed
zeroized, and an attacker with process-memory read access could still
recover credentials. Production adapters will need OS keystore integration,
separate browser contexts, credential leases and process isolation.

The adapter interfaces by themselves do not authorize external account
registration. A future staging adapter must implement an explicit
operator-approved engagement manifest and actual network egress policy,
quota/consent rules, inbox ownership, cleanup and challenge handling.
There is no CAPTCHA solver, Turnstile bypass or third-party signup here.

## Tests

```sh
go test ./internal/bunnyidentity ./internal/bunnyauthflow ./internal/tools
```

The suite checks strict persona isolation, token-redacted outputs,
rotation/revocation/expiry, account quotas, trusted sender/recipient
validation, duplicate-alias refusal and the end-to-end synthetic email OTP
workflow on ephemeral localhost HTTP fixtures. Native Windows CI executes
the same full workflow in secure and deliberately weak modes.

## Next phase

Add a stateful challenge handoff for human-controlled MFA or anti-abuse
checks, a persistent operator-approved scope policy for testing accounts,
and trusted staging adapters that never expose cookies/tokens to the LLM.
Then run controlled multi-agent comparisons with signed recorder evidence.

## v0.19 challenge lifecycle integration

The authentication coordinator now issues short-lived `email_otp`
challenge tickets through BunnyChallenge before registering a synthetic
account. After the private in-memory mailbox code is successfully exchanged
for a high-entropy bearer session, the ticket is settled using a digest of
the issued session token—not the six-digit OTP. Account enrollment fails
closed if the challenge could not be completed.

Both synthetic account tickets must complete for the end-to-end workflow
to succeed. The result reports `email_challenge_tickets_completed: 2`
without including OTP values or challenge secrets. Other challenge types
are deliberately handed to the human-approval path, not automatically
bypassed.
