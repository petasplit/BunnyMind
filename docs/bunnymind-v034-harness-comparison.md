# BunnyMind v0.34 — harness audit and integration decisions

**Scope of review:** the previously discussed agent ecosystem, supplemented by current public upstream documentation. These are *architecture patterns*, not a claim that private services have been reverse-engineered or their components copied. Features are classified as **present**, **implemented in v0.34**, **partial**, or **not implemented**.

| Agent / framework | Publicly described harness pattern | BunnyMind status and implementation boundary |
| --- | --- | --- |
| BugBunny.ai (closed platform) | URL-first assessment orchestration, authentication, tool execution and proof-oriented finding review | **Partial.** Program URL auto-intake and deterministic tool-first discovery since v0.33; authenticated browser and JS endpoints added here; no claim of feature parity with proprietary internal systems |
| DorkixAI (prior comparison) | Normal/Full mission profiles, weighted target priorities and interactive finding focus | **Present (v0.28+)** as `engagement_profile` and `finding_focus`; no wholesale third-party code copied; provenance and coverage must still be improved |
| Strix | Agent tool loop, memory compression, agent spawn graph, browser/HTTP proxy, code inspection, extensible skills, sandbox | **Partial/present.** BunnyMind has specialized roles, model/tool harness, skills, browser driver, subagent delegation and private evidence; no isolated Kali container on portable Windows install |
| PentAGI | Distinct per-flow tool sandboxes, vector memory and optional Neo4j attack graph, agent reflector and tracing | **Partial.** In-process guard, BunnyGraph, blackboard, retries and local evidence exist; isolated container runtime and full OpenTelemetry/trace graph remain separate infrastructure |
| NeuroSploit | Local model providers, specialist agents, browser workflows, attack graph and replay validation | **Partial.** Ollama, specialist roles, receipts, browser test accounts and scoped validation exist; arbitrary tool/inference autonomy remains constrained |
| RedAmon | Phase-gated, checkpointed state machine; public attack-surface graph, traffic capture, JS recon, parallel waves, human approval | **Partial.** Local graph/blackboard, activity timelines, approvals and encrypted browser HTTP capture exist; v0.34 adds passive JS discovery; full typed workflow checkpointing and deep source-map analysis remain gaps |
| Xalgorix | 22-phase methodology, WebSocket telemetry, independent finding evidence, local model provider and branded reports | **Partial.** Methodology board, SSE progress, SARIF/Markdown reports and evidence controls; phase-by-phase adaptive criteria and native PDF export remain unverified |
| BugTraceAI | Modular CLI/WEB/API engines, independent validation, model checkpoints, browser validation, MCP | **Partial.** Tool registry, MCP, agent UI, validated Python proofs, model adapter support; dedicated API-contract consumer and full model benchmark lab not yet integrated |
| Shannon | Whitebox source analysis combined with dynamic verification | **Not complete.** Project sources can be inspected via file/code tools; a trusted source-to-sink finding graph with differential confirmation is a separate project |
| Cairn | Blackboards, state-space search, frozen deterministic replay, targeted repair after UI drift | **Partial.** Shared blackboard, branch hypotheses, preserved generated scripts and signed receipts; v0.34 adds real-browser regression, but no autonomous UI-test healing |
| MAPTA/MAPT research | Coordinated specialist agents, attack hypothesis search and independent evidence judge | **Partial.** Specialized assessment roles, hypothesis tests, repeat controls and signed evidence; systematic prospective benchmark of multi-agent judge independence remains to be established |
| ProjectDiscovery Katana | Standard and headless crawling, JavaScript endpoint/XHR discovery, state deduplication, bounded interactive UI exploration, authenticated flows | **Implemented subset in v0.34.** Read-only authenticated headless Chrome, DOM links and script resource/observed XHR inventory. Interactive click graph, broader JS AST and source-map handling remain gaps |
| RedAmon/BugTraceAI's modular tools | Versioned tool capability inventory and structured evidence provenance | **Partial.** Dedicated `approved_headless_crawl` tool, authenticated run CLI and explicit regression suite added; sandboxed third-party module licensing/security review required before importing code |

## Actual v0.34 changes

- **Trusted browser flow:** operator-authored, validated login plan, one test persona, OS keyring secret references, terminal signed-in assertion.
- **One-way crawl boundary:** after the successful operator-approved login, the **same isolated Chromium** switches to GET/HEAD-only interception. No form fills, button clicks, POST, OPTIONS, or cross-origin navigation in discovery mode.
- **Network boundary:** exact HTTPS origin, pinned public IP DNS CONNECT proxy, per-session browser request cap and minimum interval, bounded run duration, no remote browser attachment or persistent user profile.
- **Extraction:** rendered DOM links, script src locations, inline JS references, loaded JS resource bodies under a size limit, browser-observed XHR/fetch/document metadata, deduped endpoint candidates labeled by source and status. Never interpret a candidate as a verified vulnerability.
- **Evidence:** private encrypted Chromium HTTP batches (when key and vault are present), SHA-256 path proofs, sampled endpoints with query/cookie/request-body stripping, UTC run summary, actor/engagement and run status. No credentials are returned to the model.
- **Quality gates:** Python Playwright browser regression against the **actual bundled React UI** using a synthetic streaming backend, plus Go security unit tests, source build and native Windows binary tests.

## Engineering next steps, not claims of completion

1. A fully sandboxed instrumented Chromium and immutable browser session snapshots/checkpoints, with controlled replay and verified authenticated-state assertions.
2. JS parser with AST, source-map provenance, route-template normalization and safe GraphQL/REST API schema discovery.
3. Authenticated SPA state-graph exploration only using explicitly approved, non-state-changing actions; use controlled staging fixtures for destructive side effects.
4. A two-stage independent evidence reviewer (request/response receipts vs model-derived claims) with confidence calibration and source-linked output.
5. A multi-tool harness that uses a single persistent cross-process budget for **all** network tools, not just the crawler/Python/browser runs sharing an output root.
6. Broad browser compatibility (Chrome/Edge/Firefox), mobile/desktop breakpoints, accessibility and visual snapshot comparisons, session resume and failure injection.

**Important:** No AI system can guarantee never to decline every possible request or guarantee bug discovery. The practical engineering objective is to act on legitimate authorized tasks without unnecessary conversational refusals, to make real tool progress visible, and to state a specific blocker when a required capability is unavailable.

### Reference material

- Strix: https://www.strix.ai/open-source-pentesting
- PentAGI: https://pentagi.com/docs/concepts/architecture/
- RedAmon: https://www.redamon.org/docs and https://www.redamon.org/how-the-agent-works
- Xalgorix: https://github.com/xalgorix/xalgorix
- BugTraceAI: https://github.com/BugTraceAI/BugTraceAI
- Cairn: https://github.com/team-poem/cairn
- Katana: https://github.com/projectdiscovery/katana

These URLs describe their respective projects; where a project has no inspected public specification, this document records a prior comparative pattern only and does not assert an undocumented current implementation.
