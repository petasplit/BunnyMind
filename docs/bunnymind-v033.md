# BunnyMind v0.33 — URL-first research and bounded authorized discovery

## Objective
When the operator provides only a public YesWeHack program link, BunnyMind
uses tools before model narration: first `program_intake` (public policy
retrieval), and then `passive_subdomains` (public CT discovery). The operator
does not need to copy the program description into the chat.

A *public program page* is not by itself an authorization to scan every linked
host. BunnyMind distinguishes public policy research, passive discovery and
active testing.

## Pipeline

1. **Program documentation:** strict URL `https://yeswehack.com/programs/<slug>`,
   DNS-pinned GET, no redirects, cookies or script execution, 512 KiB response
   cap. Save source URL, UTC, SHA-256 and size; extract HTML scope rows, excluded
   assets, testing precautions and finite first-party HTTPS origin suggestions.
   A failed or truncated retrieval is reported rather than guessed.
2. **Inactive scope proposal:** save an immutable JSON proposal under
   `~/.antares/bunnymind/program-proposals/<engagement>/`. It is explicitly
   marked `review_required` and `approved_for_active_testing=false`. No tool
   automatically activates it as an engagement manifest.
3. **Passive CT:** use a strict registrable first-party domain from parsed
   scope to query `crt.sh`. Bound to a 512 KiB response and 100 DNS name
   candidates; records source and observed hash. No discovered host is contacted.
4. **Approved active discovery:** if an independently operator-reviewed
   BunnyGuard manifest is already configured and its *exact* first-party
   HTTPS origin intersects parsed program scope and exclusions, run a
   `scoped_crawl` GET-only first pass immediately. Do not auto-expand wildcard
   domains, third-party hosts, raw IP literals or category exclusions.
5. **Evidence:** save per-page status, MIME type, body hash, byte count,
   discovered same-origin paths, elapsed timestamps and a private crawl receipt.
   No page content, cookies or personal data are copied into public reports.

## Windows command line

The main app includes these model tools; the Windows test artifact also ships:

```powershell
.\BunnyMind-program-intake-windows-x64.exe --url "https://yeswehack.com/programs/doctolib-public-bug-bounty-program"
```

This command fetches only public program metadata and may save an inactive
proposal. When scope extraction is incomplete, review the original page.

For a *separately reviewed* exact-origin BunnyGuard manifest:

```powershell
.\BunnyMind-scoped-crawl-windows-x64.exe --guard .\guard-reviewed.json --url "https://reviewed-host.example" --max-pages 8 --depth 1 --out .\Evidence
```

The command refuses missing or mismatched authorization; the example hostname
is fictional and must be replaced only with a permitted in-scope asset.

In Chat, select the Security Lead role and paste only the public program URL.
The tool timeline should show the real program fetch and, when supported,
passive CT enumeration before any model-generated summary. Active crawling
requires launching BunnyMind with `ANTARES_BUNNY_GUARD_POLICY` pointing to the
reviewed manifest and `BUNNY_PROOF_OUTPUT` to the shared evidence directory.

## Browser and crawling boundaries

The built-in `scoped_crawl` is deterministic, same-origin and read-only:
maximum 16 pages, depth 0..3, 64 KiB per response, no redirects, no cookie
reuse, no form submissions, no cross-origin navigation, query values dropped,
dangerous paths such as /logout, /delete and /reset excluded, and at least 250 ms
between requests. A persistent shared quota/lease protects Python and crawler
runners using the same evidence root, but is **not** yet global across every
Antares network tool or separate output root.

The existing separately approved browser workflow supports specific login,
SSO and test-account session flows. A fully generalized headless JavaScript
crawler with DOM actions, page-state graph and arbitrary form exploration is
**not** implemented in this milestone. Those operations need independent
per-request browser scope controls before unattended production use. Real
anti-bot/CAPTCHA protections are not bypassed.

## UI and chat regression improvements

The mobile navigation drawer now locks underlying page scrolling and closes
on Escape and route changes, with dialog semantics. The mobile project drawer
closes on Escape and session switches. Project sidebar state clears stale
project information and plan data before loading a new session. The horizontal
tab bar only maps vertical wheel input to sideways movement when overflowing.

Earlier v0.32 improvements—native chat scroll, live message visibility,
steady streaming indicator and bounded local-model pseudo-tool handling—remain.

CI includes offline scope/exclusions parsing fixtures, CT candidate filtering,
same-origin crawler tests, Go vet, frontend typecheck/build, and Windows
localhost crawler startup and private evidence tests. A passed CI does not
establish live third-party vulnerabilities.

## Technical gap against advanced frameworks

ProjectDiscovery Katana and similar crawlers combine standard crawling with
headless rendering, JavaScript endpoint extraction, configurable scope,
deduplication and browser state exploration. BunnyMind v0.33 supplies the
conservative standard-crawl baseline and integrates with the existing scoped
browser authentication harness. The next milestone should add an
authenticated, DNS-pinned, per-request browser DOM crawler, JS endpoint
classification, crawl checkpoints, redirect/identity controls, and independent
browser-based chat/sidebar regression tests.

Do not promise that any model will accept literally every prompt. The
implementation prefers actionable tool results and explicit scope/blocker
messages over generic refusals, but legal authorization, provider limitations,
safety restrictions and honest evidence reporting remain mandatory.
