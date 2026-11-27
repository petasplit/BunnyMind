# BunnyMind v0.23 — isolated Chromium authentication workflow (local fixture)

This milestone extends v0.22's owner/peer/anonymous evidence review with **real browser navigation and isolated browser authentication sessions**. It is implemented exclusively against BunnyMind's disposable numeric-loopback web application. It does **not** connect to or create accounts on third-party bug-bounty targets.

## What runs

The CLI command:

    go run ./cmd/bunny-browser-auth-demo

and agent tool **auth_browser_lab** run the same code path:

1. Start a disposable HTTP fixture on a randomly selected numeric-loopback port.
2. Generate two separate synthetic accounts under `example.test` and their own private, isolated Chromium profiles.
3. Fill the first account's registration form, submit signup, retrieve a **one-time verification code from a trusted in-process provider**, fill it into the browser, submit verification and establish a browser cookie.
4. Verify the account's identity inside that browser.
5. Repeat independently for the second account and verify that it identifies as the second persona, not the first.
6. Close browsers and destroy temporary browser profiles.

The result reports actor counts, successful steps, structured action types and local, non-signed event fingerprints. It does not print raw email addresses, OTPs, cookies, form values or browser response bodies. Codes are generated with cryptographic randomness and consumed after one successful exchange. The local session cookie is HttpOnly and SameSite=Strict.

The existing `auth_workflow_lab` remains an HTTP-level fixture; the new lab uses the actual browser transport.

## Separate origin gate in Chromium

To prevent the local browser exercise from silently contacting other destinations, a new `browser.Options.LoopbackOrigin` applies request-stage **CDP Fetch interception** to the active page before the first navigation. The session allows at most 64 page requests and only methods GET, HEAD, POST and OPTIONS to one **exact** `http://<numeric-loopback-address>:<port>` origin. It fails all others using `Fetch.failRequest`. HTTPS, hostnames (including localhost), other ports, remote debugging, existing browser profiles, stealth browser launch and proxies are prohibited for this lab.

The gate is a page-level mechanism, **not a general-purpose browser network sandbox**. It is not sufficient for real public domains, popups, browser extensions, background traffic or DNS-pinned staging egress. The local fixture also disables browser background networking through the existing launcher.

## Trusted workflow runner

`internal/bunnybrowserflow` offers an explicit `Plan` and a `Run` method with bounded steps (32), personas (4), strict local paths and selector syntax, typed operations, and a `Secrets` provider interface. The agent does not supply secret values; the local trusted provider generates and resolves them. An `operator_handoff` action requires a **trusted external callback**, and cannot be replaced by an agent-supplied approval boolean. No CAPTCHA/MFA bypass is implemented.

## Evidence, limitations, and validation

- The result can be recorded in the v0.21 privacy-safe timeline when called from the security tool.
- Unit tests cover off-origin/redirect detection, malformed paths, secret redaction, multiple isolated personas, operator handoff, local HTTP method budgets and isolated-browser option validation.
- Chromium integration tests exercise the two-persona signup/OTP flow and confirm that an off-origin request to a second local port is blocked. They skip if Chrome is unavailable; check actual GitHub Actions results before declaring success.
- There is **no third-party authorized browser adapter** yet, no real email account integration, and no live-target authentication confirmation.
- Public/staging support would require a separately reviewed egress sandbox, DNS/IP pinning, permission-scoped identity adapters, and operator approval for MFA/anti-bot handoffs.

This is a controlled, functional browser-authentication building block, not BugBunny performance parity.
