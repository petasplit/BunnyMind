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
| [Cairn](https://github.com/Ed-Marcavage/awesome-security-agent-harnesses) | Blackboard-oriented distributed exploration (catalogue description) | Agent workers collaborate through facts and task hints | Need direct repository verification before choosing components |
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

## Gaps, ordered by real-world value

1. Hard network-layer scope and egress restrictions, incl. DNS, redirects,
   browser/CDP, WebSockets, subprocesses and authorized private labs.
2. Shared engagement identity for independent subagents, with reliable claims,
   lock coordination, and resume after process restarts.
3. Independently observed and authenticated evidence receipts with trace links
   to the original request/response and negative controls; replay on fixed code.
4. Graph of inventory assets and ownership relationships, incremental refresh,
   coverage accounting and stale-result invalidation.
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
