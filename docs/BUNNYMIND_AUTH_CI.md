# BunnyMind v0.16 CI hardening

The inherited full Antares CI failed on v0.15 even though Go tests,
frontend build and native Windows smoke succeeded. The failed smoke job
logged a `bun run build` crash (`SIGSEGV`) **after** Vite had emitted
the dashboard asset bundle.

The workflow now invokes the same pinned TypeScript and Vite dependencies
through Node in the smoke job. It copies the generated dashboard assets
into the embedded server directory, builds the real CLI and local provider
fixture, then runs the same Bun-based Chrome smoke walker. The browser
smoke test is **not skipped**.

Additionally, Windows CI cross-compiles the auth-flow demo and then
starts that exact executable on `windows-latest` in two modes:

- Secure synthetic owner/foreign/anonymous access
- Deliberately weak synthetic cross-user access

The executable must establish exactly two synthetic accounts, read three
private mailbox messages, complete three OTP verifications, reject OTP
replay, maintain distinct sessions, rotate/logout tokens and distinguish
the two authorization outcomes. All traffic stays inside disposable
localhost fixtures. Neither browser anti-bot bypass nor real signup
on external sites is part of these checks.

This CI change addresses one observed Bun build crash; it does not
guarantee that all future browser or daemon startup failures are resolved.
