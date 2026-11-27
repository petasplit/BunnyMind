# BunnyMind v0.13 — native Windows smoke validation

Earlier milestones built the Windows x64 executable on Linux but did not
start it on the target operating system. Version 0.13 adds a
`windows-native-smoke` GitHub Actions job on `windows-latest`.

That job downloads the **exact Windows CI artifact** from its preceding
cross-compile job and runs the standalone local authorization demo twice:

```powershell
.\BunnyMind-authz-demo-windows-x64.exe -json
.\BunnyMind-authz-demo-windows-x64.exe -vulnerable -json
```

The secure fixture must show legitimate owner access and denial of
cross-user access. The intentionally vulnerable fixture must show the
synthetic owner's marker to the foreign synthetic user. Both must contain
eight signed synthetic observations and pass the source-level verifier.

To avoid shipping fixed bearer values in a demo, each process now creates
two independently random, in-memory synthetic test tokens using
`crypto/rand`. These tokens are never printed, stored, or sent to hosts
outside the ephemeral numeric-loopback fixture.

**This is a native Windows smoke check for the synthetic demo**, not a
complete end-to-end launch test of the full Antares desktop interface.
It does not access real accounts or bug bounty targets. The fixture and
signer deliberately run together, so its signatures are not evidence
from an independent real-world recorder.

The correct next steps for authorized staging assessments are distinct
isolated identities, explicit scope approval, network-level containment
for all relevant traffic, and independent repeatable controls.
