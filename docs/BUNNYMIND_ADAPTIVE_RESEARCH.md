# BunnyMind v0.17 — Adaptive hypothesis reasoning

The difference between a sophisticated researcher and a payload-spraying
scanner is not the size of the payload dictionary. It is the ability to
form a testable hypothesis, establish baseline and negative controls,
identify *what was actually observed*, and choose the next experiment
with high expected information gain.

The new `research_next_step` tool does this for **structured observations**
without sending HTTP requests or executing exploit strings.

## Inputs

Each observation has a unique ID, a treatment fingerprint (SHA-256), an
evidence fingerprint (SHA-256), a role (baseline, negative control or
candidate), and one recorded signal:

- `normal`, `denied`, `marker`
- `intermediary_block`
- `transport_error`, `server_error`

A case has a fixed budget of 1–64 observations and a hypothesis category
(authorization, input handling, server execution or business logic).
Duplicate observation IDs, unknown signal types, malformed fingerprints
and budgets beyond the limit are rejected.

## Reasoning rules

- No valid baseline → establish or repair the baseline before attributing
  effects to a candidate.
- No negative control → collect one before interpreting a marker.
- Indicator present in the negative control → flag likely reflection,
  contamination, mistaken test setup or an invalid oracle.
- All candidate requests blocked by an intermediary → classify the case
  as **blocked / not tested**. This is NOT evidence that the underlying
  application is safe or vulnerable.
- Transport/server failure → restore connectivity or repeat one controlled
  observation rather than escalating a vulnerability claim.
- One marker → repeat with fresh controls.
- Multiple distinct evidence fingerprints reporting the marker → request
  **independent signed reproduction**, not automatic confirmation.
- Repeated identical candidate treatment without evidence → change the
  hypothesis instead of repeating low-information requests.
- Budget exhausted → stop and review, never silently expand the scan.

The `mint_benign_canary` action returns a random marker prefixed with
`BUNNY_BENIGN_`. It is *not* an exploit payload. Cryptographic randomness
makes repetition unlikely but cannot guarantee it has never appeared
anywhere before.

## Why this differs from naive WAF evasion

A WAF's denial is a distinct signal about the intermediary, not a prompt
to mutate an exploit indefinitely. The planner recommends classifying
the block and establishing where the observation was made. It does not
generate obfuscated RCE payloads, automated protection bypasses, or
operational exploit chains.

In a future operator-approved environment, a model can propose novel
**hypotheses and low-impact observations**, while this component enforces
evidence budgets and negative controls. Independent verification and
network containment are mandatory before an unattended assessment.

## Tests

```sh
go test ./internal/bunnyresearch ./internal/tools
```

These are deterministic unit tests of reasoning rules, not a head-to-head
benchmark of real vulnerability discoveries. The original evidence
fingerprints are caller-provided and are not signed or authenticated by
this planner.
