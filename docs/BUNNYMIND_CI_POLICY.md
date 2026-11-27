# BunnyMind CI concurrency and build policy

Three workflows use a per-workflow, per-source-branch GitHub Actions
concurrency group:

- `BunnyMind Foundation CI`: focused Go regression tests and harness
  microbenchmarks.
- `BunnyMind Windows x64 build`: produces a 7-day downloadable CI artifact,
  not an automatically published release.
- `CI`: inherited Antares unit tests, vet, frontend build and browser smoke.

When a new commit or duplicate PR event arrives for the same branch, the
previous pending/in-progress run for the same workflow group is cancelled
and the newest run is preferred. This reduces repeated builds and cost during
active development; it does not alter test semantics or automatically merge PRs.

## Release gate

Only consider merging a stacked draft PR after the latest head SHA passes
its focused tests, upstream CI and Windows build, and after manual review
of scope boundaries and evidence claims. Builds passing does not establish
autonomous vulnerability-discovery performance.

The main branch stays unchanged until PRs are reviewed and merged explicitly.
