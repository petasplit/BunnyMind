# BunnyMind harness comparison — November 27, 2026

This is a source- and documentation-based comparison, **not** a head-to-head
penetration-testing benchmark. Marketing claims are marked as such.
No code from competitors is copied into BunnyMind; compare design patterns and
respect each project's license.

| Project | Publicly described harness | Distinguishing elements | Tradeoff and verification caveat |
| --- | --- | --- | --- |
| [Antares](https://github.com/enowdev/antares/blob/main/docs/harness.md) | Bounded model/tool loop, repetition guard, goals and judge model, subagent delegation | Go/Windows, session memory, role tools, browser, approval modes | Security roles have no engine-wide scope enforcement; no public independent discovery benchmark |
| [BugBunny](https://bugbunny.ai/) | Closed hosted continuous security engineer | Asset inventory, validated findings, bug-fix PR workflow, connected repos/cloud | Closed implementation. Product examples are not independent accuracy benchmarks |
| [DorkixAI](https://x.com/DorkixAI) | Closed paid managed pentester (publicly promoted via X) | Advertises long engagements and follow-up on individual findings | Source, model, harness, independent benchmarks and handling of sensitive data not verified |
| [Pentest-Swarm-AI](https://github.com/Armur-Ai/Pentest-Swarm-AI) | Coordinator + shared memory/blackboard; priority and lifecycle controls | Multi-agent team, planned/dispatched work, cleanup hooks and CI reporting | Some advertised features and quantitative superiority claims remain unverified outside project |
| [RedAmon](https://github.com/samugit83/redamon) | Checkpointed typed state graph and routing to different agents | Neo4j knowledge graph, durable state, evidence-to-fix PR pipeline | Heavy multi-container deployment; benchmark scores are author-reported |
| [Shannon](https://github.com/KeygraphHQ/shannon) | Worker isolation, source-assisted stages, resumable workspaces | Source-to-runtime links, PoC-gated reporting, SARIF/CI | Focused on source-accessible apps, requires Docker and capable model |
| [Strix](https://github.com/usestrix/strix) | Multi-agent graph with API contracts and run budgets | Browser+API, reports/patches, CI hooks | Actual performance depends on chosen model and target |
| [Xalgorix](https://github.com/xalgorix/xalgorix) | Extended methodology and separate verifier | Recheck before marking a finding verified, local Ollama support | Numerous high-impact capabilities; no independently reproduced general-purpose benchmark verified here |
| [depthfirst](https://depthfirst.com/agentic-pentesting) | Closed runtime security validation with code linkage | Replay after fix, static-to-dynamic evidence timelines | Hosted/closed, no transferable full harness |
| [Cairn](https://github.com/kgreenhalgh/pentest-cairn) | Shared fact/intent/hint blackboard; workers explore an unknown state space | Decentralized OODA reasoning, parent-child task projects, adaptive intents | Competition results are author-reported; this architecture needs strong fact provenance and bounded worker cost |
| [ChainReactors cyber-harness](https://github.com/chainreactors/cyber-harness) | Composable Go extension lifecycle | Models, tools, knowledge and collaboration share one extension contract | AGPL-3.0; conceptually reusable, but source reuse requires license analysis |
| [BreachWeave](https://github.com/Ed-Marcavage/awesome-security-agent-harnesses) | Manager/Solver/Observer separation (catalogue description) | Observer holds termination decision independent of task solvers | Public competition claims do not establish success on ordinary web applications |

## What v0.4 adds

BunnyMind's original Antares agent loop already had goals, short-term memory,
verification and delegation. v0.4 **adds offline orchestration**:
task dependency DAG, priority queue, bounded leases and retries, crash-resilient
state files, and a claim/heartbeat/complete/fail/status tool.

This is the **state-control plane**, not the executor. No subagents automatically
consume the queue. The evidence digest required to complete tasks is
caller-supplied and does not attest real vulnerability proof. The v0.2 offline
evidence reviewer likewise evaluates provided observations, not authenticity.


## BunnyMind v0.5 and v0.6 additions

**v0.5 — BunnyNet:** The opt-in guarded mode now uses a dedicated read-only
HTTP transport that validates exact origins, dial-time IP addresses and
optional narrow private CIDR exceptions. It blocks redirects and restricts
responses to 64 KiB. This applies only to `scoped_read`, not to arbitrary
browser, MCP, plugin or subprocess networking. Legacy HTTP tools are denied
when the explicit guarded mode is active. It is not universal containment.

**v0.6 — BunnyGraph:** A per-session versioned inventory graph now stores
caller-supplied origins, endpoints, services, repositories and dependencies,
with typed edges and source labels. Successive snapshots yield deterministic
added/removed/changed sets. This is **not** live discovery or evidence
attestation; graph fingerprints and provenance labels must come from trusted
instrumentation before being treated as observations.

Both additions have focused regression suites and are staged in draft PRs
rather than merged to main.


**v0.7 — BunnyBlackboard:** Structured observation records are shared by
engagement rather than by Antares session. The board tracks a bounded,
deduplicated ledger of short non-sensitive descriptions, source categories and
claimed evidence hashes. A different session can request reproduction or
reject an entry; no agent can promote it to a verified vulnerability directly.
Session-based separation is not cryptographic identity verification, and
separate Antares processes still lack cross-process locking.

**v0.8 — BunnyPlanner:** BunnyGraph's optional `update_and_suggest`
action creates a deterministic list of review-only task suggestions (maximum
64) from inventory changes. It uses fixed priorities, collapses duplicate
changes and produces task IDs compatible with the v0.4 task board. No task
is automatically scheduled or executed, and caller-supplied inventory changes
do not become verified security facts merely by producing a task.

## v0.9 — Trusted recorder signatures

BunnyMind v0.9 adds an Ed25519 verification package and an offline agent tool
for signed observations from a separately operated recorder. A verified
signature provides provenance binding to one lab signer, not proof of
vulnerability exploitation. The helper CLI can generate/sign synthetic
observation files in an isolated recorder environment; the model-facing
tool can only verify using a pinned public key. This closes part of the
gap between v0.2 caller-supplied evidence and authenticated provenance;
full independent request replay and source-to-runtime verification remain
unimplemented.

## v0.11 — locally observed and signed evidence

The v0.11 loopback recorder adds a concrete observed HTTP capture path:
a strictly local-only GET transport records actual fixture responses,
computes marker flags and response digests, then signs the observations
with an isolated recorder key. A synthetic fixture and JSON plan exercise
this in tests and from a CLI.

This is limited to numeric loopback IPs and is not a substitute for
independently reproducing vulnerabilities in authorized real applications.
Evidence authenticity still depends on signing-key isolation, a trusted
recorder process and sound control experiments.

## Gaps, ordered by real-world value

1. Extend v0.5 network checks from the restricted reader to all relevant
   browser/CDP, WebSocket, tool/plugin, subprocess and proxy egress paths.
2. Authenticate engagement-wide reviewer identities, add process-safe locks,
   and automatically link v0.7 observations to v0.4 task queues.
3. Independently observed and authenticated evidence receipts with trace links
   to the original request/response and negative controls; replay on fixed code.
4. Ingest v0.6 graph snapshots from trusted captures and source scans, then
   connect v0.8 review suggestions to the durable engagement coordinator with
   explicitly approved scheduling and stale-result invalidation.
5. Documented authentication test personas and non-production test sessions.
6. Bounded, resumable verifier/fix/review workflows with operator approvals,
   deterministic lab success gates, cost/time budgets and rollback.
7. Trusted CI and benchmark runs: fixed datasets, five or more repetitions,
   model/environment/version pins, false positives and resource usage.

## Engineering rules

- Scope before execution; fail closed, not an instruction in a prompt.
- No live exploit or scanning against third-party targets in CI.
- Distinguish **reported**, **consistent observations**, **independently
  replayed**, **impact validated**, and **fixed**.
- Avoid counting titles, agent counts, marketing demos or GitHub stars as
  evidence of security assessment quality.
- Keep raw tokens/credentials out of the public repository, issues and Actions
  logs. Use synthetic data and isolated staging only.

## Licensing

Antares itself is Apache-2.0, and upstream notices are retained. Other
projects may be AGPL/GPL/commercial; BunnyMind imports no source from them.
This file reflects publicly available descriptions on Nov 27, 2026.
