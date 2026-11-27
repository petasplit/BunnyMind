# BunnyMind v0.29 — generated Python proof scripts and encrypted evidence

## What is implemented

BunnyMind now compiles an operator-approved test plan into an executable, standalone `scenario.py` using Python's standard library. It saves the complete source and its SHA-256 fingerprint before execution. The script performs up to 24 strictly scoped GET/HEAD requests, with at least two candidate observations and two negative controls. Requests to real external HTTPS origins use BunnyMind's DNS-pinned local CONNECT proxy. Only numeric-loopback fixtures may use HTTP.

The trusted Go parent starts Python in isolated mode, enforces a fixed timeout, reads the short-lived captured transcript, and independently verifies request and response hashes and the marker actually present in the response body. The verdict `repeated_candidate_with_negative_controls` is **not** a proven security vulnerability. A failed control or incomplete body produces an inconclusive result.

### Every saved proof run contains

- `scenario.py`: exact generated Python script; credentials are not embedded
- `plan.json`: the approved tests and harmless marker, with individual candidate/control cases
- `validation.json`: statuses, timestamps, evidence file name, SHA-256 fingerprints and caveats
- `transcript.enc`: AES-256-GCM-encrypted HTTP request/response records, including headers, captured bodies and test-account cookies when supplied through the OS keyring
- `README.txt`: explanation of all files and validation limitations

The raw transcript contains up to 64 KiB of response body per case, with explicit truncation flags; it is a normalized HTTP capture, not the raw encrypted TLS bytes. The plaintext intermediate evidence file is deleted after encryption.

## Windows setup and commands

First initialize the vault key in the operating system credential store:

    go run ./cmd/bunny-python-proof --init-key

Example `python-plan.json`, to be used only with explicitly authorized test endpoints:

    {
      "engagement_id": "approved-example",
      "run_id": "case-0001",
      "origin": "https://staging.example",
      "marker": "BUNNY-OWNED-TEST-MARKER",
      "min_interval_ms": 250,
      "cases": [
        {"sample_id":"candidate-1","kind":"candidate","method":"GET","path":"/owned-resource"},
        {"sample_id":"control-1","kind":"control","method":"GET","path":"/denied-resource"},
        {"sample_id":"candidate-2","kind":"candidate","method":"GET","path":"/owned-resource"},
        {"sample_id":"control-2","kind":"control","method":"GET","path":"/denied-resource"}
      ]
    }

Replace these illustrative paths only with assets you are authorized to test. The BunnyGuard manifest must match the engagement, exact origin, approved methods and request/rate budget.

    go run ./cmd/bunny-python-proof --guard guard.json --plan python-plan.json --out .\BunnyMindEvidence

To keep credentials out of generated code, provision a test identity session cookie in the existing OS keyring:

    go run ./cmd/bunny-approved-auth --set-secret owner:session_cookie

Add a `persona` field such as `owner` to a case to use that pre-provisioned test session. The value is injected only into the restricted Python process environment, and saved only inside encrypted raw capture.

To export the complete private HTTP transcript for an authorized bounty triager, explicitly acknowledge that it may contain credentials or private test-account records:

    go run ./cmd/bunny-python-proof --out .\BunnyMindEvidence --export-run case-0001 --confirm-sensitive

The resulting `TRIAGE-FULL-HTTP-PRIVATE.json` contains base64-encoded captured request and response bytes. Transfer only through the security program's approved confidential channel.

## Agent operation and UI

Set `ANTARES_BUNNY_GUARD_POLICY`, `BUNNY_PROOF_PLAN`, and `BUNNY_PROOF_OUTPUT` to operator-controlled paths before starting BunnyMind. The agent can invoke `python_proof_run` with an empty argument object. It cannot replace the target, script code, or credentials. The tool returns a sanitized result and records a timeline evidence reference.

Open **Engagement → Python evidence** in the dashboard. Select a saved run to view the exact Python script, its hash, the validation outcome, request/control statuses and whether an encrypted raw transcript exists. The dashboard never decrypts the private capture.

## Encrypted browser screenshot and HTTP evidence

Set `BUNNY_BROWSER_CAPTURE_DIR` to a private local folder before launching the approved Chromium workflow. The browser then saves encrypted PNG evidence of login, OTP, CAPTCHA and verification pages and post-submission states. Results contain screenshot filenames, sizes, timestamps and SHA-256 hashes.

The same vault can also retain Chrome CDP-observed HTTP request URLs, headers, submitted form data, response headers and available response bodies per authentication step. These private fields are encrypted; the agent sees only hashed endpoint identifiers and encrypted artifact references. CDP bodies may be unavailable or truncated and are explicitly labeled. A browser CDP capture is a reconstructed observation, not a wire-level packet dump.

To view a private screenshot locally, supply the directory containing its `.enc` file:

    go run ./cmd/bunny-python-proof --out .\PrivateChromeCaptures\hashed-engagement --export-screenshot owner-otp-1 --confirm-sensitive

The decrypted PNG is created locally under restrictive file permissions. The web API does not serve private screenshots or raw HTTP evidence.

## Turnstile and other verification

The adaptive browser already recognizes OTP fields, retrieves the code from an operator-controlled IMAP mailbox or enrolled test TOTP seed, and enters it into the discovered field. With this upgrade it saves encrypted before/after screenshots and may use a genuine Chrome pointer click on a visible **official Turnstile or reCAPTCHA test-key widget**. It does not forge CAPTCHA tokens or bypass unsolved production challenges; a real production challenge requires ordinary provider approval, an authorized test exemption, or legitimate user action.

## Limits

The generator produces bounded, scenario-specific Python source rather than arbitrary AI-written exploit code. Repeated positive/negative observations are not definitive proof of RCE, SQL injection, authorization bypass or severity. The Python runner has independent request and pacing limits, but the existing BunnyGuard invocation ledger does not yet reserve every subprocess request across concurrent processes, so only one proof runner should execute per engagement until that accounting is implemented. No live third-party security finding is claimed from these synthetic tests.
