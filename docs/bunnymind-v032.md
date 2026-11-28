# BunnyMind v0.32 — usable Windows chat, streaming and scoped tool replies

## What was wrong

The v0.31 chat view grouped user/assistant turns inside React Virtuoso,
each with an independent sticky prompt and a second explicit bottom-pinning
system. During streaming, Virtuoso remeasured growing rows while the page
was also assigning scroll positions. As a result user messages could vanish
from view, upward scrolling could snap back, and the composer could visibly
jump when progress status changed.

A 7B local coding model also occasionally replied with a JSON-shaped
pseudo-tool-call as **text**, or returned an opaque refusal when given only
a bug bounty program link and no configured test target.

## Implemented corrections

- The transcript is now a regular browser scroll container with native
  overflow. User messages and assistant replies remain mounted as ordinary
  DOM elements during generation.
- An inner ResizeObserver watches real content height and follows streamed
  text only while the user is at the bottom. Manual wheel/keyboard scroll
  unpins; scrolling back near the bottom re-enables following.
- The streaming indicator occupies a fixed-size row and truncates long status
  labels rather than resizing the composer every second.
- A YesWeHack program link without an exact in-scope asset now receives an
  explicit explanation of the missing Target/Scope and BunnyGuard configuration.
  The program listing itself is **not** automatically treated as a probe target.
- A small local model's exact JSON pseudo-tool-call can be recognized and
  dispatched only when it specifies an available read-only tool. It cannot
  directly synthesize arbitrary shell commands, HTTP mutations or unauthorized
  security probes. For security assessments, fallback is disabled without a
  valid matching manifest and scope.
- Added unit tests for the scroll-follow policy, prompt-recognition and
  rejected mutating/malformed pseudo-tool-calls.

## Windows test procedure

1. Stop the existing BunnyMind server using `STOP_BUNNYMIND.cmd`. Preserve
   `%USERPROFILE%\\.antares` with your existing Ollama settings and sessions.
2. Extract the new Windows ZIP to a **new** directory, not over an old
   installation. Run `START_BUNNYMIND.cmd`.
3. Open `http://127.0.0.1:8787` and perform one hard reload
   (`Ctrl+Shift+R`) to clear old hashed frontend script references.
4. Start a new chat and enter a benign request that produces several
   paragraphs. Confirm the user message appears immediately, the assistant
   grows while streaming, and wheel scrolling upward stays put until you
   deliberately return to the bottom.
5. Verify the composer position is stable while the progress timer increments.
6. If the agent is asked to scan a YesWeHack program listing, it should explain
   why a concrete in-scope target and locally configured BunnyGuard manifest
   are required before making network requests, not claim an unperformed scan.

## Remaining limitations

Native DOM rendering is optimized for reliability in typical sessions, not
thousands of historical messages. A future virtualizer would require proper
scroll-anchor ownership and browser tests before reintroduction.

A working local model does not guarantee every tools-capable instruction
will be followed. A 7B coding model is not a substitute for accurate scope
verification. Tool availability, credentials and operator permissions still
control which actions can run.

These tests are local, bounded and do **not** demonstrate real vulnerabilities
on Doctolib or YesWeHack.

Source: https://github.com/petasplit/BunnyMind/pull/33
