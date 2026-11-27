# BunnyMind v0.28 — popup SSO, WebAuthn test flows, secure finding chat and SARIF

## What this milestone extends

v0.28 builds on v0.27's **real approved external HTTPS** browser workflows and makes the authentication/triage experience more complete. It is a review branch, not a protected-branch merge. The operator still defines every permissible HTTPS origin and POST path, request limit, and test persona.

### Redirect and popup SSO

The Chromium CDP transport now uses `Target.setAutoAttach` with `waitForDebuggerOnStart`, then configures the same request-stage `Fetch` gate before resuming newly attached page targets. All popup targets remain subject to the local DNS-pinned HTTPS CONNECT proxy as well as approved-origin checks. The active CDP session can switch to an allowed IdP popup and restore the app tab; the adaptive runner can check whether a known signed-in indicator appeared on the parent after an OAuth/OIDC callback.

Targets opened on unlisted hosts are closed or their requests are denied. OAuth query strings are never included in the emitted finding or timeline fields. A maximum of four popup targets is supported. No popup is allowed to add an origin to the approved scope.

**Provider limitation:** Authentication sequences spanning closed browser/device flows, native dialogs or unusual cross-window messaging still depend on what the actual provider supports; compatibility with external Entra ID/Google/Okta tenants has not been proven in this repository.

### Hardware WebAuthn and virtual test authenticators

Real **hardware-backed passkeys** are supported through Chromium's normal platform WebAuthn UI where the operating system exposes an enrolled security key. The device's user-presence or biometric confirmation is still required by the WebAuthn authenticator; BunnyMind cannot silently defeat that security property.

For expressly authorized staging tests, the operator can enable a **virtual WebAuthn CTAP2 authenticator** with resident-key and user-verification emulation. A test credential is created by the normal application registration flow and lives only in its disposable browser profile. This is not a physical security key and does not prove compatibility with a named hardware vendor.

Example configuration additions:

```json
{ "passkey_mode": "virtual_test", "allow_natural_captcha": true }
```

`passkey_mode` belongs in `adaptive.json`. `allow_virtual_passkey: true` must also be explicitly set by the operator in `scope.json` before `virtual_test` is accepted. Use `passkey_mode: platform` to invoke the actual OS authentication flow and expect the device to request its normal presence/verification. The program does not store or impersonate physical WebAuthn keys.

### Production CAPTCHA

`allow_natural_captcha: true` can let an already-verified, provider-generated CAPTCHA response complete normally without asking for an additional operator action. This does **not** generate a challenge solution or bypass the target's verification. If the page still presents an unsolved challenge, the workflow fails closed or uses the preexisting operator handoff. Site owners can configure allowlisted test accounts, approved testing environments or official provider test keys to permit unattended compliance testing; production anti-bot defenses are never disabled by BunnyMind.

### Finding-chat dashboard

Open **Engagement → Findings → Discuss** beside any recorded finding. The panel supports repeated questions, bounded 40-turn history, and reload-safe per-session storage. Responses are rule-based and grounded exclusively in the finding's recorded status, severity, evidence-presence flags and digests. The API requires the existing dashboard authorization. Conversation histories are stored with private file permissions and never return raw PoC strings, authorization tokens, HTTP cookies or sensitive target URL query parameters.

**Important:** This is interactive evidence-focused chat, not a free-form remote LLM with action authority. It cannot independently verify an exploit, generate a live PoC, or mark findings confirmed. An AI-powered follow-up may be added later behind independent evidence and tool-approval gates.

### SARIF 2.1.0

**Engagement → Export SARIF** downloads a redacted machine-readable findings list. Records contain safe origins, CWE identifiers, recorded severity/status, title with obvious secrets redacted, and a stable finding fingerprint. Raw requests, PoCs, credentials, query strings and endpoint paths are not emitted. Triage statuses remain **unattested** until independently verified.

### Competitor capabilities and roadmap

The detailed public-source comparison is in `docs/bunnymind-competitor-review-2026-11.md`: BugBunny, DorkixAI, PentAGI, Strix, Shannon, MAPTA, MAPT, Xalgorix and other agent frameworks. This milestone prioritizes practical verified integration gaps and does not copy other companies' proprietary code.

## Tests

Expected CI jobs:

- Foundation: test/vet `bunnyfindingchat`, `bunnysarif`, and the existing safety and auth packages.
- Dedicated Chromium: real popup navigation and parent-tab restoration with request scoping; WebAuthn virtual authenticator setup; existing shadow DOM/SSO/login tests.
- Application: full Go and frontend tests plus browser smoke.
- Windows x64: cross-compiled executable and native fixture smoke.

CI tests use fixtures and synthetic identities, not third-party targets. Green CI is a correctness signal only for the tested paths, **not proof of production provider reliability**.

## Configuration and limitations

Continue using the v0.27 operator-owned `guard.json`, `scope.json`, `adaptive.json` and the OS-keyring secret references. All actions remain within BunnyGuard and the DNS-pinned proxy. Physical passkey prompts cannot be treated as bypassable, and production CAPTCHAs can only advance through legitimate provider/site-owner mechanisms. An independent OS-level egress sandbox is still recommended for potentially hostile pages. No external site was scanned in this change.
