# BunnyMind — autonomous security research architecture

## Goal

Build a high-confidence, local-first research agent that spends time on
**information gain and evidence quality**, not raw request counts or
marketing-oriented exploit claims.

### Identity and login plane

A permitted application adapter must implement:

1. **Scope and authorization manifest:** exact allowed origins, explicit
   owner permission, allowed testing windows, account quota, rate limits,
   roles and allowed test data.
2. **Registration:** create disposable *test* accounts using an authorized
   organization-controlled or test-domain email address. Do not infer
   permission to register identities on an unrelated site.
3. **Private inbox adapter:** read only the specific test account's messages,
   match the expected sender and account, extract and submit allowed OTPs,
   and avoid exposing codes to the LLM or logging them.
4. **MFA and human steps:** if external login requires a personal device,
   CAPTCHA, or a provider's anti-abuse challenge, request authorized
   operator interaction instead of silently bypassing safeguards.
5. **Credential/session vault:** encrypted storage with short-lived leases,
   zero raw-token tool outputs, separate browser contexts/cookies per role,
   refresh and logout, logout invalidation, audit/cleanup.
6. **Verification:** compare owner, foreign, and anonymous behavior with
   signed positive and negative controls, independent replay and remediation
   rechecks.

v0.16 implements this workflow **only** for isolated synthetic localhost
fixtures. No live-account provider or mailbox integration exists yet.

### Adaptive research plane

The model should reason through an explicit cycle:

**Observe → hypothesize → pick a falsifiable low-impact experiment →
collect baseline and controls → evaluate the response source →
reproduce independently → update the investigation graph.**

For WAF/intermediary refusals, avoid treating the result as a proof about the
application. Distinguish network controls from application authorization.
New research directions should be justified by previous observations,
expected information gain, scope, request budget and operator permission.
Do not promise globally never-before-used payloads—this cannot be proven.

A real agent should explore hypotheses with varied evidence sources and
independent verifier agents rather than endlessly obfuscating a payload.
The v0.17 tool currently evaluates reported outcomes and proposes safe next
experiment types. It does not autonomously execute or verify them.

### Harness integration targets

- Structured state: BunnyHarness task DAG + BunnyBlackboard + BunnyGraph
- Scope: BunnyGuard and a later process-wide network-isolation boundary
- Identity: v0.16 synthetic authenticated session runner and future
  operator-approved staging adapters
- Provenance: signed lab receipts, before/after build measurements
- Decision support: v0.17 hypothesis feedback and benign canaries
- Evaluation: BunnyBench signed scoring on repeatable concealed lab cases
- Release: Windows native runtime, fully green CI, reproducible artifacts

### Unfinished work

Provider adapters, transactional cross-process state, sandbox-wide egress
isolation, independent signer isolation, authenticated browser automation,
persistent per-role session vaults, automatic scheduling of candidate
verification, actual local LLM inference runs, reproducible comparison to
competing security harnesses, and production-grade deployment identity
attestation.

Do not describe these as implemented until end-to-end tests establish
that they function.
