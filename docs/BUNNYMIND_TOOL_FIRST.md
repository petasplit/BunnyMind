# BunnyMind v0.20 — tool-first, concise execution mode

## Intended user experience

When the operator pastes an **authorized security-assessment description,
target URL and scope** into BunnyMind, it should *work*, not deliver an essay
about what it plans to do.

The v0.20 runtime now recognizes a **complete, validated engagement**:

1. BunnyGuard's validated manifest exists in
   `ANTARES_BUNNY_GUARD_POLICY`.
2. The current request contains a URL whose scheme, hostname and port
   exactly match one of `allowed_origins` in the manifest.
3. The user selected a security role, or the request explicitly includes
   security-assessment terminology and scope/authorization language.
4. The actual model toolset exposes `scoped_read`.

A request meeting these conditions automatically selects the security role
when none was selected, appends concise execution rules, and sets the first
model turn's `ToolChoice` to `required`.

Any opening narration streamed by the model is buffered. If the model
actually calls a tool, that opening text is discarded rather than shown or
saved as an assistant preamble. If it fails to call any tool, the genuine
provider response is surfaced rather than falsely claiming an action ran.

## Real-time action updates

Once a tool passes approval and BunnyGuard preflight, the agent emits short
UI notices tied to **actual** tool execution, for example:

- `scoped_read` → `Inspecting in-scope URL`
- `inventory_graph` → `Mapping observed assets`
- `auth_workflow_lab` → `Testing synthetic sign-in`
- `verify_lab_receipts` → `Checking evidence`
- `research_next_step` → `Evaluating test signals`

A denied tool emits its actual failure, **not** an optimistic action status.
The full tool-call/result stream remains available for audit; this is a
presentation preference, not a way to hide what the agent did.

The reader's existing `RequiresApproval` flag is removed only for
`scoped_read`: a non-mutating GET/HEAD tool with exact approved origins,
per-connection IP verification, refusal of redirects and proxies, response
caps, and BunnyGuard request budgets. The operator has explicitly
approved this narrow capability through the engagement manifest. Tools
with broader effects retain their existing approval requirements.

## Fail closed and do not fabricate

If the guard manifest is absent or invalid, a URL is out of scope, or
`scoped_read` is missing from the active toolset, **forced network
tool-first mode does not activate**. General chat also does not switch
into security mode merely because it mentions a URL.

This is not a universal network sandbox. It does not authorize arbitrary
browser, shell, plugin or subprocess traffic. The current
`auth_workflow_lab` runs only a disposable localhost fixture; it does not
log into the provided target. Never display `Signing in` for a target
unless a real approved target adapter was used.

The model can still be denied by a provider that does not support required
tool selection. When that occurs, the true blocker is reported.

## Example config

```json
{
  "engagement_id": "my-authorized-lab",
  "allowed_origins": ["https://lab.example.test"],
  "allowed_methods": ["GET", "HEAD"],
  "max_network_calls": 50,
  "min_interval_ms": 300
}
```

Then set `ANTARES_BUNNY_GUARD_POLICY` to the manifest path and supply an
in-scope target URL plus security-assessment scope in the chat. BunnyMind
attempts the first tool call without a preamble.

## Tests

```sh
go test ./internal/agent ./internal/bunnyguard ./internal/tools
```

Tests cover matching and nonmatching origins, absent/invalid policies,
auto-selection versus ordinary chat, provider first-tool choice and
truthful action-status labels. CI also runs the usual full Antares tests.

No real third-party host is crawled by CI.
