# BunnyMind v0.4: Durable Investigation Harness

Research influences: Antares's existing repetition guard and goals; RedAmon's checkpointed state graph; Pentest-Swarm-AI's blackboard; Shannon's resumable workers. **New implementation**, not code copied from other licensed projects.

## How it works
The agent now has a new offline tool, `investigation_board`, exposed to the security toolset. A task plan describes a bounded directed acyclic graph of work: inventory, analysis, verification, review, report or remediation.

The board:
- Persists per Antares session under the state directory with a SHA-256-derived filename, 0600 permissions and atomic replacement.
- Validates dependencies, detects cycles and refuses unknown task kinds.
- Schedules higher priority ready tasks first (stable ID tie-break).
- Claims tasks using a session-owned expiring lease, maximum active count and retry limit.
- Recovers expired leases after a restart; stale owners cannot complete another worker's lease.
- Requires a 64-character SHA-256 evidence reference before completion.
- Preserves blocked, failed, running and completed states across agent conversations.
- Does not run shell commands, browser requests, HTTP requests or scanning tools.

### Actions
- `plan`: creates a task DAG once, cannot overwrite it.
- `claim`: picks the highest priority dependency-ready task.
- `heartbeat`: extends current task lease.
- `complete`: stores an evidence digest and unlocks downstream dependencies.
- `fail`: retries within budget or blocks the task.
- `status`: displays current task states and ready work.

## Trust model and limitations
A digest shows that an agent *claims* to have evidence; the scheduler cannot tell if it has reproduced a vulnerability. Evidence must be checked independently through BunnyEvidence and actual instrumentation. Task completion itself does not mean a vulnerability is confirmed.

The store is single-process concurrency safe. It does **not** provide cross-process locks or distributed consensus. Different subagent sessions do not yet share the same board. The tool stores short task titles as supplied; do not include credentials, PII or raw exploit artifacts in titles.

This stage is coordination infrastructure, not an autonomous pentest benchmark or a network scope firewall. Guarded sessions can call `investigation_board`, but shell/browser tools remain unavailable until a stronger network isolation layer is built.

## Tests
```sh
go test ./internal/bunnyharness ./internal/tools ./internal/agent ./internal/config
```

Cases include graph cycles, unknown dependencies, priority ordering, concurrency ceiling, leases/restart, failure/retry, stale owner rejection, digest requirement, tampering, and file-path isolation.
