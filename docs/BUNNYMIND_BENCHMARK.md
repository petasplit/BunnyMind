# BunnyBench: local benchmark scoring

BunnyBench is a standalone **offline scoring engine** included in the
BunnyMind fork. Its purpose is to compare repeated runs with the exact same
ground-truth cases and score *supported reports*, not just requested URLs or
generous claims.

It DOES NOT generate attacks, launch scanners, read your browser or evaluate a
model. It accepts a JSON study containing a fixed manifest and trial records.

## Run

```shell
go test ./internal/bunnybench ./cmd/bunnybench
go run ./cmd/bunnybench -input benchmarks/bunnybench/illustrative.json
```

The included file is **illustrative synthetic data, not a completed test of
Antares or any other model**. Replace it with records from an isolated,
instrumented local laboratory and map the final agent report's claim IDs
manually.

## Score definition

Each trial supplies three independent sets:

- `proof_events`: case IDs for which the **lab** recorded the expected proof signal.
- `passed_controls`: case IDs for which the **lab** recorded the expected
  negative-control result.
- `reported`: case IDs actually claimed in the agent's final report.

A true positive requires **all three** for the same case. Reports with
missing proof, missing control, or unknown case IDs are classified as
unsupported. Reports containing the same claim multiple times are counted
only once. Known cases not supported by the report are missed.

`precision = supported / distinct_reported`

`recall = supported / all_ground_truth_cases`

`proof_coverage = lab_proofs / all_ground_truth_cases`

A no-report trial has precision=0 and recall=0; this convention prevents
a vacuous result from appearing perfect. Group-by-model aggregates are
macro-means over complete trials, not an accuracy guarantee.


## Signed scoring alternative (v0.10)

`bunnybench-signed` consumes Ed25519-authenticated bundles from a separately
operated v0.9 lab recorder. Unlike the simple `bunnybench` input, it does not
accept self-declared proof events and negative-control success lists as
standalone evidence. The scorer derives these gates from valid, pinned-key
signed observation bundles, then applies the same precision/recall rubric.

See [Signed benchmark scoring](BUNNYMIND_SIGNED_BENCHMARK.md) and
[Signed evidence receipts](BUNNYMIND_SIGNED_RECEIPTS.md). Signing authenticates
the recorder, **not the truth of the observation**, and is not independent
reproduction of an exploit or proof of impact.

## Benchmark discipline

Use the same versioned ground truth and permitted interactions for each
model and heuristic baseline. Run at least five independent trials per
configuration and record prompt, model, quantization, elapsed time, tool
failures, report, and raw lab logs. Keep case labels hidden from the agent
until after the run.

**Limitations:** The scorer does not authenticate submitted lab events,
validate a CVSS score, inspect the natural-language report or prove the
observations were independent. A malicious or mistaken input can mislead
scores. Use a trusted local lab and preserve its original logs for review.
Never interpret the included synthetic example as actual model performance.
