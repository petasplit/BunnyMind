# BunnyMind v0.31 — authenticated, offline-verifiable Python evidence

## Purpose

The v0.29/v0.30 Python runners already save complete encrypted HTTP transcripts, exact generated Python scripts and independent negative-control summaries. v0.31 prevents a normal run from being reported as complete until its **six saved artifacts** have been authenticated with a private, key-derived evidence seal.

The seal is not a vulnerability confirmation, a timestamp authority or a proof of independence. It is a local tamper-evidence mechanism. A party controlling the local key can forge a new seal; an external timestamp or independent second-party attestation is still required for stronger provenance.

## Automatically sealed files

Each successful Python proof run now includes `seal.json` covering exactly:

- `scenario.py`: exact executed script source;
- `plan.json`: approved request cases, identities and origin;
- `validation.json`: response status, hashes and negative-control summary;
- `report.md`: redacted analyst-readable report;
- `README.txt`: evidence-handling notes;
- `transcript.enc`: AES-256-GCM encrypted full HTTP request/response observations.

The manifest records SHA-256 and size for every ciphertext/script/report file, run and engagement identity, decrypted transcript SHA-256, and UTC seal creation time. It is authenticated using HMAC-SHA256 with a domain-separated MAC key derived from the operating-system-protected evidence encryption key. The plaintext transcript and session cookies are never written to the seal.

The verifier rejects missing files, modified files, changed plan/script checksums, missing ciphertext, failed AES-GCM authentication, a different run/engagement ID, an altered seal MAC, and symlinks in required evidence paths. Creation of a second seal in the same directory fails rather than replacing the original.

## Offline verification on Windows

Initialize a private evidence key through the earlier proof CLI if needed:

```powershell
go run ./cmd/bunny-python-proof --init-key
```

After a successful adaptive campaign, verify each recorded round:

```powershell
go run ./cmd/bunny-audit --run ".\BunnyMindEvidence\authresearch01\authresearch01-r01"
```

Expected high-level result:

```json
{
  "engagement_id": "approved-staging",
  "run_id": "authresearch01-r01",
  "files_verified": 6,
  "result": "integrity_verified_impact_unassessed",
  "limitation": "..."
}
```

The command performs no HTTP requests and prints no raw cookies, HTTP response bodies or decrypted private account information. To share results, send a *private, appropriately minimized* encrypted evidence bundle with the report; do not post raw session cookies or personal records to public GitHub discussions.

## Windows executable from GitHub Actions

In PR #32, open the **BunnyMind Evidence Auditor Windows x64** workflow run, then download the `bunnymind-evidence-audit-win-x64` build artifact after it passes. It contains `bunny-audit-windows-amd64.exe` and `SHA256SUMS.txt`. Verify the executable checksum before using it. The executable is a local offline auditor; it does not contain or export your encryption key.

Run it in PowerShell on Windows 10/11:

```powershell
.\\bunny-audit-windows-amd64.exe --run ".\\BunnyMindEvidence\\authresearch01\\authresearch01-r01"
```

The Windows workflow runs audit unit tests before publishing the executable. A draft PR and artifact are not a signed production release; review source and test results before relying on the binary.

## Security model and remaining gaps

1. Seals require the operator's existing OS-keyring evidence key; a copied bundle cannot be verified by someone who lacks that key or an independently issued verification attestation.
2. Run sealing is per-round. The parent campaign `campaign.json`, `study.json` and `report.md` are not yet authenticated as one campaign-wide summary; verify each sealed round separately.
3. The Python runner remains intentionally constrained to the approved scenario inventory. It is not a general untrusted-model Python executor.
4. Status differences and stable response markers are **observations**, not proof of an exploitable vulnerability. A separate impact demonstration and independent triage are required.
5. Production CAPTCHA and hardware-backed passkey security are not bypassed. Only permitted test-account flows and provider-sanctioned test-key behavior are automated.

## Tests

```bash
go test ./internal/bunnyaudit ./internal/bunnyscript ./internal/bunnyautoprobe ./cmd/bunny-audit -count=1
go vet ./internal/bunnyaudit ./internal/bunnyscript ./internal/bunnyautoprobe ./cmd/bunny-audit
```

Included regression cases cover a clean seal/verify roundtrip, all six artifact mutations, manifest mutation, wrong key, duplicate seal, refusal to verify unsealed material, and symlink substitution. Existing loopback-only Python campaign tests exercise the new automatic run seal.
