# BunnyMind v0.10 — signed-receipt benchmark scoring

The existing `bunnybench` CLI accepts the caller's claimed proof events and
negative-control outcomes. Those inputs are useful for simple fixtures but
can be fabricated by a model or user.

The new `bunnybench-signed` CLI and
`bunnybench.ScoreSignedStudy` require **Ed25519-signed bundles** produced by
the separately operated v0.9 BunnyReceipt recorder.

## Scoring gates

For each ground-truth case in a trial:

1. A bundle must match the trial's exact engagement, run and case IDs.
2. Each receipt must verify against the pinned public key.
3. Every sample ID must be unique, and the marker hash and HTTP origin
   must be consistent within the bundle.
4. At least two signed positive samples and two signed negative controls
   must report consistent, non-reflected marker observations.
5. The agent must actually include the case ID in its reported findings.

Only then does BunnyBench count one supported report. All other reported
cases count as unsupported; unsigned/unreported cases remain misses.

Any invalid signature, unknown case, duplicated case bundle, or cross-run
evidence rejects the entire study rather than silently dropping evidence.

## Usage

```sh
go test ./internal/bunnybench ./internal/bunnyreceipt ./cmd/bunnybench-signed

go run ./cmd/bunnybench-signed \
  -input /isolated/lab/study-signed.json \
  -public /isolated/lab/recorder-public.key \
  -output /isolated/lab/results.json
```

Study JSON is shaped as:

```json
{
  "engagement_id": "lab_1",
  "manifest": {
    "benchmark": "fixed-lab-v1",
    "cases": [{"id": "C1"}, {"id": "C2"}]
  },
  "trials": [{
    "run_id": "run_1",
    "model": "local-test-model",
    "reported": ["C1"],
    "bundles": []
  }]
}
```

An empty `bundles` array yields zero supported findings; no success is
assumed. Bundle contents follow the v0.9 BunnyReceipt schema.

## Important limitations

- A valid signature establishes a recorder key was used. It does not prove
  the signed observations are correct; an untrusted recorder can sign false
  marker flags.
- A score is not an autonomous pentesting benchmark unless a real agent
  was run, fixed ground truth was kept hidden, controls were instrumented,
  and the original evidence was retained for independent audit.
- No actual model inference, HTTP traffic, bug exploitation or code patching
  happens inside this scorer. Never describe synthetic tests as a
  comparative win over another security tool.
