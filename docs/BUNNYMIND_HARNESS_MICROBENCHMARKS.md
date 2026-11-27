# BunnyMind harness microbenchmarks

CI executes deterministic Go microbenchmarks and publishes its output as a
GitHub Actions artifact named `bunny-harness-microbench`.

Current workloads:
- `BenchmarkBoardStatus64`: load and validate a persisted 64-task DAG.
- `BenchmarkCompare1024Assets`: diff 1024 synthetic inventory assets with
  one changed fingerprint.
- `BenchmarkSummary128`: load and validate 128 shared, synthetically authored
  observation records with a 50-entry result cap.

Run locally:
```sh
go test ./internal/bunnyharness ./internal/bunnygraph -run '^$' \
  -bench '^Benchmark' -benchtime=25x -benchmem
```

Measure nanoseconds/op and allocations/op with `benchstat` or comparable
statistics over multiple runs on identical hardware. CI hardware is shared,
so times should be treated as relative engineering diagnostics, **not**
independently comparable scores against other frameworks.

These tests do not run a language model, browser, scanner, or authorized
exploit, and do not measure vulnerability detection, false positives, or
overall agent success. Comprehensive head-to-head evaluation remains future
work requiring pinned targets/models, identical permissions and independent
evidence verification.
