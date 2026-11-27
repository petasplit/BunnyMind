# BunnyMind v0.16 — Autonomous synthetic authentication workflows

BunnyMind now includes a **fully executable localhost-only authentication
lab**. A trusted test workflow can create two brand-new synthetic user
accounts, read their verification messages from an isolated in-memory mailbox,
extract six-digit OTP codes, submit those codes, establish two distinct
bearer sessions, and verify cross-user/anonymous resource access.

The workflow also exercises session rotation, new login via a fresh OTP,
replayed OTP rejection, logout and invalidated session tokens.

## Capabilities demonstrated

- Generate unique email identities under reserved `example.test` (no
  deliverable external email addresses involved)
- Register the identities using HTTP POST to a disposable local fixture
- Receive verification messages from `no-reply@bunnymind.test` in an
  in-memory mailbox that **has no HTTP inbox-read endpoint**
- Read the message, identify the six-digit code, and submit it once
- Maintain separate owner/foreign bearer sessions, rotate one, log out
  another, and verify old sessions are rejected
- Compare an owner-only resource under the owner, foreign and anonymous
  identities; optionally simulate deliberate cross-user exposure
- Return only small evidence summaries, booleans and bounded request counts

The test-server OTP expires after five minutes and accepts at most
three failed numeric submissions per challenge. New login challenges
invalidate old pending OTPs. Real session tokens, verification messages,
account emails and resource markers are **not returned** to the agent.

## Agent tool

`auth_workflow_lab` is available in the Antares security toolset, including
opt-in BunnyGuard mode. It accepts only one optional boolean:

```json
{"deliberate_exposure": false}
```

There is **no target URL**, external email provider, CAPTCHA capability,
credential store, shell action, or browser automation option. The tool
starts its own local fixture and tests it; it cannot create accounts on
arbitrary websites.

## Standalone test executable

```sh
go run ./cmd/bunny-authflow-demo
go run ./cmd/bunny-authflow-demo -weak
go test ./internal/bunnyauthflow ./internal/tools
```

A native Windows workflow builds and runs the same demo against its
disposable localhost fixture with two synthetic identities. Tests verify
secure denial and the intentionally weak mode. None of this is evidence
of a live production bug.

## Architectural next steps for real authorized engagements

The **next phase** should introduce pluggable *operator-approved* registration
adapters with explicit domain scope, consent/ToS awareness, an account budget,
reliable session recording, isolated test inboxes, explicit MFA approval when
necessary, and secret stores inaccessible to the language model.

Real-world OTP/MFA flows must use appropriately authorized test mailboxes
and sessions. Third-party CAPTCHA and anti-bot safeguards should not be
silently bypassed; when an interaction needs a human, the workflow should
pause for permitted operator action.

The adaptive testing engine should choose evidence-driven hypotheses,
negative controls and bounded experiments. It must distinguish blocked
requests from disproven hypotheses and must not assume evasive payloads
or exploit success without independently reproduced signals.

**Current boundary:** This code only tests BunnyMind-owned synthetic
loopback fixtures. Full network isolation for external browsers/plugins
is still missing, and no third-party account was created.
