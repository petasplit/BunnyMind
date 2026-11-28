# BunnyMind v0.35 — Five infrastructure gaps

This draft adds source-aware static JavaScript analysis, credential-safe authenticated
browser replay, a persistent engagement-wide network-call budget, sandboxed
offline specialist jobs, and an independent encrypted-evidence judge.

## 1. TypeScript AST + ECMA-426 source maps

The cross-compiled `BunnyMind-js-ast-windows-x64.exe` uses the TypeScript
compiler's real JavaScript AST. It analyzes *files offline*; it does not execute
target scripts or contact their hosts. It identifies static literal references
from `fetch`, `axios`, `XMLHttpRequest.open`, `new URL`, and endpoint-style
properties, records source positions, and eliminates cross-origin URLs, query
values, control-sensitive routes and dynamic expressions that cannot be
resolved reliably.

Use a locally acquired, approved JS file and optional local source map:

```powershell
.\BunnyMind-js-ast-windows-x64.exe --file ".\captured\bundle.js" --origin "https://reviewed-target.example" --map ".\captured\bundle.js.map"
```

The analyzer validates source map v3 / ECMA-426 VLQ mappings and associates
AST locations with original source names and line/column numbers. Original
`sourcesContent` is never emitted. It does **not** automatically download
source maps; automatic retrieval would require a separately authorized,
budgeted GET to each exact origin.

The headless crawler automatically invokes the bundled AST executable on
bounded inline and loaded JavaScript when the companion EXE is available.
It labels regex fallback when the AST helper is absent or fails.

## 2. Fresh authenticated replay (no exported live sessions)

```powershell
.\BunnyMind-browser-replay-windows-x64.exe --guard ".\guard-reviewed.json" --scope ".\browser-scope-reviewed.json" --login ".\trusted-login.json" --crawl ".\headless-crawl.json" --out ".\Evidence"
```

Requires preapproved HTTPS origins, a trusted test account in Windows
Credential Manager, and an initialized OS evidence key. The runner
authenticates *twice*, each time in a new temporary Chromium profile. It
switches to read-only GET/HEAD exploration following each approved login and
compares normalized endpoint/page inventories. An AES-256-GCM replay capsule
records signed-in assertion count, config hashes and two report fingerprints,
**not cookies, tokens, browser profiles or live sessions**. A divergence is
reported rather than hidden.

This is deterministic fresh-login *replay by recipe*, not direct restoration of
an arbitrary expired authenticated session.

## 3. Shared persistent network-call budget

All guarded direct requests (`scoped_read`, `program_intake`,
`passive_subdomains`) reserve one unit against the same persistent ledger.
The Python proof engine, adaptive proof campaigns, HTML crawler, approved
browser login, adaptive login and authenticated headless crawler reserve
their worst-case network budget before executing. Replay consists of two
separate browser allocations. Changing the evidence-output directory does not
reset the ledger. Cross-process reservations are serialized and fail closed on
exhaustion or a missing ledger.

Default location: per-user OS config directory under
`BunnyMind/shared-network-quota`. Trusted operators may set
`BUNNY_SHARED_QUOTA_ROOT` to an absolute private directory to share the same
ledger across distinct instances. Unspent bulk reservations are **not**
automatically refunded. The existing engagement-specific pacing and
restricted egress continue to apply.

This does **not** guarantee a single global limiter for arbitrary host tools,
third-party plugins outside guarded mode, independently launched external
software or different OS users. Security engagements disable unmetered plugin
pre/post tool hooks.

## 4. Sandboxed offline specialists

```powershell
.\BunnyMind-specialist-sandbox-windows-x64.exe --profile ".\trusted-specialist.json" --evidence ".\Evidence"
```

Requires Docker Desktop configured for **Linux containers**, a *locally
available immutable image digest*, and an operator-written profile. It runs
with `--network=none`, `--read-only`, `--cap-drop=ALL`,
`--security-opt=no-new-privileges:true`, a nonroot user, bounded CPU,
memory, PIDs and wall-clock timeout, and a single **read-only** bind
mount of the selected input workspace. Standard output and error streams
are encrypted in the local vault rather than exposed to the model.

The agent-facing `sandbox_specialist` tool accepts **no** command/URL/script
arguments and only uses `BUNNY_SPECIALIST_SANDBOX_PROFILE`. Docker is never
installed automatically, and if isolation is unavailable the runner stops;
there is no fallback to unsandboxed local shell. Containers reduce, but do not
eliminate, risks from malicious code and untrusted image contents.

## 5. Independent evidence judge

```powershell
.\BunnyMind-evidence-judge-windows-x64.exe --run ".\Evidence\my_run_01"
```

`bunnyjudge` independently reads the sealed manifest, opens the locally
AES-GCM-encrypted transcript, recomputes raw request, response and body hashes,
verifies approved paths/sample identities/markers and separately checks
negative controls. This second parser does not trust the generator's reported
verdict. When there are at least two consistent candidates and two successful
negative controls it returns
`replicated_observation_needs_independent_impact_review`.
It never asserts `impact_verified`.

The Python proof runner now automatically invokes this judge after sealing
the six saved artifacts, writing its verdict as a separately authenticated
`independent-judge.enc`. No raw private HTTP bytes appear in the model's
judge response. This is independent **code-path** verification, not an
independent third-party authority or independent exploitability assessment.

## Windows validation

The Windows build artifact includes the standalone AST parser and the three
new Go CLI tools above. CI runs TypeScript parser/source-map tests,
source-inventory/path-redaction tests, cross-process quota tests,
Docker sandbox argument tests, AES-GCM judge and replay tests, Go vet,
and the existing Chromium/Chat/sidebar Windows smoke suites.

**Truthful remaining limitations:** Automatically fetching source maps across
a live authorized application is not enabled. Full browser-state snapshot
serialization is intentionally not supported; replay always reauthenticates.
Docker isolation requires Docker Desktop and an audited pinned image.
Global quotas cover BunnyMind's *guarded* network-capable assessment paths,
not arbitrary independent network software. A verified response marker is
not proof of a high-impact vulnerability.
