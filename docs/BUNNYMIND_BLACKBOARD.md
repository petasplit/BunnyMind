# BunnyMind v0.7 — shared engagement blackboard

## Purpose

Antares already delegates tasks, and BunnyMind v0.4/0.6 adds an individual
task board and inventory graph. Those stores are per agent session and do not
let independent agent sessions exchange a small structured observation.

**v0.7** adds `engagement_blackboard`, an offline Go tool with `record`,
`list`, `status`, and `review` actions. It shares **a single board per
BunnyGuard engagement identifier**, rather than per agent session, so
subagents started with the same validated `ANTARES_BUNNY_GUARD_POLICY`
manifest can read each other's records.

## Trust and security model

- An explicit valid BunnyGuard engagement manifest is required, even for
  reading an empty blackboard. A model cannot supply a different engagement
  name in tool arguments.
- Agent session IDs are SHA-256-hashed for author/reviewer references; raw
  session identifiers are not emitted in the output.
- Records have stable IDs, optional asset IDs, short bounded labels, source
  categories (captured HTTP, source inventory, operator, model inference), and
  a SHA-256 **reference** to separately retained evidence.
- Source labels and evidence hashes are **claims**, not authenticated facts.
  No attempt is made to verify that a caller has captured, reproduced, or
  correctly interpreted the underlying behavior.
- Duplicate IDs with identical immutable payloads are idempotent; conflicting
  updates are rejected. The board caps at 256 records per engagement.
- A different agent session may make a **one-time editorial decision**:
  `needs_reproduction` or `rejected`. An agent cannot review its own record
  or directly mark a security issue `verified` or `confirmed`.
- Labels are restricted to 160 bytes, with obvious credential keywords
  rejected. This is NOT a comprehensive PII/secret detector, so never put
  customer data, session cookies or credentials in the tool arguments.
- Data is stored per engagement under `ANTARES_HOME/bunnymind/blackboard`
  using private permissions and atomic writes. There is one shared mutex per
  state directory **inside one Antares process**.

## Limitations and roadmap

1. Session separation is based on the application-provided session ID, not
   cryptographic operator or agent identity; do not treat different session IDs
   as independent identity attestation.
2. Two **separate Antares processes** sharing the same filesystem do not have
   interprocess locking. Deploy one Antares process per state directory until
   a transactional SQLite/Postgres backend is added.
3. Neither the blackboard nor its SHA-256 evidence references authenticate
   observations. Verification still requires a trusted recorder and an
   independently replayed control experiment within authorized scope.
4. The v0.4 task DAG, v0.6 graph and this v0.7 blackboard are not yet
   automatically synchronized. A separate orchestration layer should make
   them cooperate without trusting model-authored priority changes.
5. The opt-in v0.5 restricted HTTP reader remains the only guarded network
   route; browser, plugin, external MCP, shell and process-wide egress are not
   universally confined.

## Tests

```sh
go test ./internal/bunnyblackboard ./internal/tools ./internal/bunnyguard
```

10 isolated tests cover shared engagement records, restart/reload, denial
of self-review, conflicts, bounded writes, safe labels, corruption, concurrency,
privacy of session identifiers, and cross-engagement separation.

This addition improves **agent coordination**, not demonstrated vulnerability
discovery performance.
