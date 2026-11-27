# BunnyMind v0.30 — adaptive Python evidence campaigns and model-guided safe hypothesis synthesis

## What changed

BunnyMind v0.29 generated and executed one fixed Python plan. **v0.30 can now inspect a trusted inventory of permitted endpoints, generate new Python scenarios, interpret captured evidence, and decide whether to repeat or change its next test.** This is real Python execution with retained source and encrypted request/response captures, not hypothetical output.

The automatic adaptation is deliberately bounded: approved GET/HEAD methods, 1–12 test-owned candidate paths, 1–12 distinct negative-control paths, 1–8 rounds, and no more than 96 requests per campaign. Each round uses two candidate observations and two negative controls. It cannot silently add targets, invent arbitrary exploitation payloads, defeat CAPTCHA, or access external assets beyond the engagement rules.

## Autonomous loop

1. Load a strict BunnyGuard manifest and an operator-owned endpoint inventory. Reject unknown fields, unapproved paths, dangerous URL encodings, unsafe actors, request pacing below the engagement minimum, or budgets exceeding the engagement allowance.
2. Choose the next candidate/control pair. Compile a **new, inspectable Python script** with the exact approved GET requests. Save its source and SHA-256 before execution.
3. Execute Python in isolated mode under a 10-minute campaign timeout. External HTTPS connections use the pinned DNS/allowlisted HTTPS proxy; private HTTP is reserved for numeric-loopback fixtures.
4. Verify that the captured request, observed status line, response body hash, timestamp, and marker all match the encrypted raw HTTP evidence. Markers embedded in the candidate's own request are explicitly rejected as reflection.
5. If a candidate produces repeated signals with uncontaminated negative controls, run a fresh script for **independent repetition with the same approved endpoint**. If it fails, move to the next approved candidate. Stop at the configured request/round limit.
6. Save `campaign.json`, a campaign-level `report.md`, and a per-run folder containing `scenario.py`, `plan.json`, `validation.json`, `report.md`, and `transcript.enc`.

The strongest possible automatic conclusion is `replicated_observation_unverified` — **not** an independently verified vulnerability or impact. Repeated responses from the same test harness can still be false positives.

## Example trusted inventory

File `adaptive-proof.json`:

```json
{
  "engagement_id": "approved-staging",
  "campaign_id": "authresearch01",
  "origin": "https://staging.example",
  "marker": "BUNNY-TEST-OWNED-RESOURCE",
  "candidate_paths": ["/owned/resource-one", "/owned/resource-two"],
  "negative_control_paths": ["/test/denied"],
  "candidate_persona": "owner",
  "control_persona": "peer",
  "max_rounds": 4,
  "max_requests": 16,
  "min_interval_ms": 250
}
```

This example intentionally uses fictional names and endpoints. For a real authorized target, all candidate and control URLs must refer to test resources/accounts that the operator controls and is permitted to examine. Store each test persona's session cookie through the existing operating-system credential store; never place it into the inventory JSON.

## Windows CLI

Initialize the evidence key once if not already initialized:

```powershell
go run ./cmd/bunny-python-proof --init-key
```

Run the autonomous, bounded study:

```powershell
go run ./cmd/bunny-adaptive-proof --guard guard.json --spec adaptive-proof.json --out .\BunnyMindEvidence
```

The resulting layout is:

```text
BunnyMindEvidence/
  authresearch01/
    study.json
    campaign.json
    report.md
    authresearch01-r01/
      scenario.py
      plan.json
      validation.json
      report.md
      transcript.enc
    authresearch01-r02/
      ...
    drafts/
      idea_<hash>/
        scenario.py
        oracle.py
        idea.json
        plan.json
```

## AI-selected hypotheses without arbitrary source execution

With `BUNNY_ADAPTIVE_PROOF_SPEC`, `BUNNY_PROOF_OUTPUT`, and `ANTARES_BUNNY_GUARD_POLICY` pointing to trusted local files, the security agent gets two new tools:

- `python_hypothesis_draft`: the AI selects a **semantic theme** (`authorization_boundary`, `session_boundary`, `input_consistency`, `status_differential`, or `marker_provenance`) and integer indices pointing to operator-approved candidate and control paths. BunnyMind compiles the proposal to exact `scenario.py` and separate offline `oracle.py`, but does not send a network request from the draft operation. Both scripts are preserved with SHA-256 hashes. Malformed indices, unsafe themes, and arbitrary Python are rejected.
- `python_adaptive_proof_run`: performs the bounded sequential campaign with an empty argument object; no raw model-generated code or target URLs are accepted. It returns only sanitized assessment metadata, with all captured requests and responses stored encrypted locally.

The offline oracle takes a saved `validation.json` and compares candidate/control statuses, marker presence, reflection flags and truncation. A positive result is labeled `unverified_observation`. It never sends network traffic.

## Evidence viewer and reporting

**Engagement → Python evidence** now indexes single-run captures, nested adaptive campaign rounds and AI hypothesis drafts. Select an item to inspect exact generated Python code, its SHA-256, a sanitized validation summary, or the draft's independent offline oracle. The UI does not decrypt session cookies, request/response bodies or screenshots.

To export a complete private HTTP transcript, use the existing local `bunny-python-proof --export-run` mechanism after navigating to its run directory; adaptive captures are stored in the nested campaign folder. Never commit decrypted evidence to a public repository or attach sensitive third-party user data to an unrestricted issue.

## Verification and limitations

- Test fixtures show that the engine tries an inconclusive approved candidate, switches to a promising candidate, and repeats that candidate in a separately generated Python run; it retains every script and AES-GCM encrypted capture.
- Separate regression checks verify that reflected request markers cannot pass the proof oracle, even with HTTP 200 responses and apparently successful negative controls.
- The AI can now **synthesize and preserve bounded Python scenarios and custom offline oracle code**, but it cannot execute arbitrary unreviewed Python from an LLM. That distinction protects external services and keeps test cases reproducible.
- The engine has not been validated against live bug-bounty assets in this milestone. A real target needs explicitly current authorization, a bounded manifest, test personas and permission for the intended methods.
- Production Cloudflare Turnstile and other CAPTCHA controls are not bypassed. Official provider test keys, site-owner-approved exceptions, naturally completed challenges, and legitimate user verification remain the supported routes.
- Python evidence runners sharing the same `BUNNY_PROOF_OUTPUT` root now reserve their *maximum planned requests* in a persistent engagement quota ledger **before executing**. A separate execution lease prevents two proof processes from interleaving requests and defeating the intended pacing. Both mechanisms use atomic exclusive file creation. Unused reservations are not automatically refunded after failures or crashes.
- These ledgers cover the Python proof runners sharing **one output directory**. Other BunnyMind network tools and separately configured output directories are not yet unified under a single operating-system-level global quota. The Python execution lease and quota lock fail closed; an interrupted process may leave a stale `.lock` file that the operator must investigate and clear manually after confirming no worker remains.

## Related work

See the prior v0.29 technical documentation for encrypted evidence export and OTP screenshot capture, and `docs/bunnymind-competitor-review-2026-11.md` for comparisons with BugBunny, DorkixAI, Strix, PentAGI, Shannon and other discussed toolchains.
