# BunnyMind competitor architecture review — 27 November 2026

Evidence levels: **verified in public source/docs** means a published description or code entry was available, not a benchmark reproduced by BunnyMind. **Claimed** means the vendor reports a capability that has not been independently measured in this project. **Planned** means not implemented here.

## Comparator matrix

| Tool / research | Publicly described strengths | BunnyMind state after v0.28 | High-value missing capability |
|---|---|---|---|
| BugBunny.ai | Black-box and white-box coverage, verified findings, continuous changes/CVEs, proof records, repository-linked fix PRs, authenticated HAR, web/mobile/cloud | Scope-bound browser auth, evidence ledger, HAR metadata, GitHub PR workflow, vulnerability evidence reviews | Full source-to-runtime trace, continuous CVE regression, patch PR automation, independent real target benchmark |
| DorkixAI | Normal/Full modes, prioritized additional targets and time budgets, per-finding conversations; claimed autonomous login and escalation | Mission profile, evidence-grounded finding chat, test identity workflows | Prospective multi-target execution metrics and independent escalation verification |
| PentAGI | Go orchestration, multiple agents, containerized tooling, episodic/working/vector memory, optional knowledge graph | Graph, durable board, timeline, bounded research next-step tool, local model selection inherited from Antares | Stronger graph/episodic memory reconciliation and isolated worker-per-task egress policy |
| Strix | Multi-agent web/API exploration, dynamic tools and submitted PoCs (vendor claims) | Specialist roles, evidence controls, scope-limited browser and reports | Explicit machine-backed candidate verification and comparative benchmark |
| Shannon / Keygraph | Source-aware multi-stage taint/route analysis, authenticated testing, resumable CI, patch validation and SARIF | Existing repository tools, engagement reporter, v0.28 SARIF metadata | True code-to-endpoint provenance, static/dynamic reconciliation and remediation regression engine |
| MAPTA | Agentic web testing benchmark, resource-efficient orchestration, early stopping | Rate/request budgets, bounded state transitions, per-target missions | Cost and false-positive benchmark for our actual models; adaptive stop decisions based on measured evidence |
| MAPT (research) | Type-checked plan/verify/reflect loop, dual-memory critic and deterministic execution | Planner, durable tasks, per-step evidence/status; bounded review suggestions | Formal decision critic and re-run stability measurement |
| Xalgorix | Phase-based autonomous testing, WebSocket telemetry, multi-provider models, finding management, exports, AgentMail and resumable scans | Existing Antares toolset, auth flow, timeline, v0.28 findings chat and SARIF | Reliable external test mailbox provisioning, interruption/resume UX, independent oracle-based proof capsule |
| PentestGPT / HexStrike / CAI | Agent harnesses and tool orchestration (CAI is archived per public project lists) | Existing specialist/tool plugin system | More rigorous model/tool reproducibility matrix and version-pinned skills |
| Fabio | Mentioned in user-supplied social context; exact repository/product not reliably verified in this research | No unverified code copied | Identify exact original repo and license before architectural comparison |
| Frost Cyber Mini / CyberKimi | Local LLM model candidates rather than autonomous infrastructure by themselves | Existing model-provider architecture | Reproducible local quantized-model benchmark on 6 GB VRAM; no claims of model fine-tuning without measured training |

## Changes implemented in the current branch

1. New scoped popup attachment: paused Chromium targets receive their own CDP `Fetch` request gate before resuming; a multi-step IdP flow can switch into the approved popup and verify completion on the parent app page.
2. WebAuthn test adapter: disposable CTAP2 virtual authenticator for operator-approved staging scenarios. Existing physical authenticators remain controlled by the actual OS/device policy.
3. Production CAPTCHA: read only an already produced provider response, never inject solver or fake token. If an actual challenge remains unsolved, require a provider-compliant site-owner exemption or legitimate user action. Production CAPTCHA evasion is **not** claimed.
4. Finding-chat: dashboard discussions tied to a real finding, capped persistent conversation history, evidence-status digest, secret-avoidance, session isolation. Responses are deterministic and evidence-grounded; this is not a remote LLM chat persona.
5. SARIF 2.1.0 export: recorded findings mapped to categories and severity without raw exploit details, marked unverified unless independently reproduced.

## Priority recommendations for future work

- **P0: independent proof validation**: signed machine-reproducible benign oracles and negative controls, plus explicit result provenance. Existing manual triage cannot be treated as a mathematical proof.
- **P0: test the new popup and WebAuthn adapters against operator-controlled OAuth/passkey fixtures**. CI success proves compilation and the scoped harness, not compatibility with all IdPs.
- **P1: source-to-runtime mapping**: a read-only parser/indexer for route definitions, data access, dependency inventory and code references linked to observed endpoints.
- **P1: a memory/critic loop**: retain sanitized failed checks and avoid repeating identical attempts; track token/network budgets, candidate error bars and resource use.
- **P1: secure isolated runtime**: per-task disposable containers and OS-layer egress rules, not just browser CDP/HTTP proxy checks.
- **P2: remediation PR workflow**: root-cause-linked patch suggestions and tests in a review branch, never direct protected-branch writes.
- **P2: CI regression and continuous inventory**: compare an approved new build against a frozen baseline and open issues for new regressions rather than raising scan volume.

## Relevant public sources

- BugBunny official: https://bugbunny.ai/ and https://bugbunny.ai/blog/how-to-use-bugbunny
- DorkixAI publicly posted details: https://www.sotwe.com/DorkixAI (third-party mirror; unverified claims)
- PentAGI: https://pentagi.com/docs/concepts/memory/ and https://vxcontrol.com/
- Shannon: https://github.com/KeygraphHQ/shannon and https://github.com/KeygraphHQ/shannon/blob/main/docs/keygraph-platform.md
- Strix: https://github.com/usestrix/strix
- MAPTA research: https://arxiv.org/abs/2508.20816
- MAPT memory research: https://ieeexplore.ieee.org/abstract/document/11572126
- Xalgorix: https://github.com/xalgorix/xalgorix
- Comparative review with dated sources: https://blog.ostorlab.co/9-open-source-ai-pentest-tools-2026.html
- Chrome WebAuthn test protocol: https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/

## Important limitations

Third-party source licenses and trademarked branding are not copied. Every external scan needs explicit permission and bounded test-account scope. No production bot-defense defeat or hardware-user-presence bypass is included. The current branch must pass GitHub CI before merging; proprietary competitors' internal infrastructure and claims cannot be certified from public descriptions.
