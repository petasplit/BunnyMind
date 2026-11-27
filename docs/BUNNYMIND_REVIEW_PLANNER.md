# BunnyMind v0.8 — incremental review planning

The new `bunnyplanner` package produces bounded deterministic **review task
suggestions**, derived from a v0.6 BunnyGraph inventory diff.

The `inventory_graph` tool now offers an additive `update_and_suggest`
action. It performs the same snapshot update as `update`, then returns the
diff together with up to 64 review tasks. The existing `update` response
remains unchanged for backwards compatibility.

A task suggestion has a stable hash-derived ID, kind `review`, priority,
a short title without raw asset identifiers, and a retry budget. Priority
is fixed by change type:

- Changed assets: 5
- Added assets: 4
- Removed assets: 3
- Added/removed relationships: 2

Results are deterministic regardless of input order; repeated IDs are
collapsed. Diffs with more than 64 unique changes are truncated with an
explicit dropped count. Invalid identifiers and graph relation names fail
before suggestions are emitted.

These tasks are **not automatically scheduled or executed**. An operator or
agent must explicitly submit the suggestions to `investigation_board.plan`
within the relevant session. That board is still per session; the v0.7
engagement blackboard is separate and cannot by itself authorize testing.

A caller-supplied inventory diff may contain errors or fabricated changes.
The suggestions are NOT evidence of discovered assets, proof of a
vulnerability, or permission to send network requests.

Test:
```sh
go test ./internal/bunnyplanner ./internal/bunnygraph ./internal/tools
```
