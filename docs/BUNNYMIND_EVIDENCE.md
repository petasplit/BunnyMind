# BunnyMind v0.2: Offline evidence-review tool

The ```review_evidence``` tool accepts synthetic or captured HTTP observations
and checks whether the claimed output marker is consistently present in at least
two submitted positive samples and absent from at least two submitted controls.

It is intended to reduce false positives, not to authorize or run any
additional tests. No requests are executed.

## Example

```json
{
  "finding_id": "F-001",
  "marker": "PROOF-12345",
  "observations": [
    {"sample_id":"p1","kind":"positive","method":"GET","request_url":"http://127.0.0.1:8765/health","response_status":200,"response_body":"PROOF-12345"},
    {"sample_id":"p2","kind":"positive","method":"GET","request_url":"http://127.0.0.1:8765/health","response_status":200,"response_body":"PROOF-12345"},
    {"sample_id":"c1","kind":"control","method":"GET","request_url":"http://127.0.0.1:8765/health","response_status":403,"response_body":"denied"},
    {"sample_id":"c2","kind":"control","method":"GET","request_url":"http://127.0.0.1:8765/health","response_status":403,"response_body":"denied"}
  ]
}
```

The result is either ```consistent-provided-observations``` or ```inconclusive```.
It includes SHA-256 digests, statuses and evidence gaps, but **not**
request or response bodies, raw URLs or the marker itself.

**Limits:** All samples must share an exact scheme/host/port; at most 32
observations; each response body is capped at 128 KiB. A marker appearing
in a positive request is a potential echo and prevents a consistent result.

**Crucial distinction:** This tool does not authenticate the observations,
replay HTTP traffic, validate security impact or establish the underlying
vulnerability. A caller could supply fabricated or identical results.
Only an independent verifier that replays within declared scope can
produce stronger verification evidence. Do not publish sensitive raw traffic
as tool arguments without separately reviewing permissions and retention.

Run: ```go test ./internal/bunnyevidence ./internal/tools ./internal/bunnyguard```
