package tools

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "os"
 "path/filepath"
 "strings"

 "github.com/enowdev/antares/internal/bunnyauthz"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)

// assessAuthzReceiptsTool is verification-only and cannot capture requests,
// load private keys, inject credentials or claim production exploitability.
type assessAuthzReceiptsTool struct{}
func (assessAuthzReceiptsTool) Name() string { return "assess_authz_receipts" }
func (assessAuthzReceiptsTool) Description() string {
 return "Evaluate two Ed25519-signed, loopback-only lab authorization bundles: "+
  "synthetic owner vs anonymous, and synthetic foreign user vs anonymous. "+
  "Returns cross-persona marker/denial observations, not proof of a live exploit. "+
  "Only a pinned recorder public key is loaded; no network calls are made."
}
func (assessAuthzReceiptsTool) RequiresApproval() bool { return false }
func (assessAuthzReceiptsTool) UntrustedOutput() bool { return true }
func (assessAuthzReceiptsTool) Schema()map[string]any {
 return schema(map[string]any{
  "plan":map[string]any{"type":"object","description":"Local lab metadata: engagement_id, run_id, case_id, origin, resource_path, marker."},
  "owner_bundle":map[string]any{"type":"object","description":"Signed owner-positive/anonymous-control bundle."},
  "cross_user_bundle":map[string]any{"type":"object","description":"Signed foreign-positive/anonymous-control bundle."},
 },"plan","owner_bundle","cross_user_bundle")
}
func (assessAuthzReceiptsTool) Execute(_ context.Context,in Input)Result {
 if strings.TrimSpace(in.SessionID)=="" { return Errorf("authorization evidence assessment requires a session") }
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if policyPath=="" { return Errorf("authorization evidence assessment requires an active BunnyGuard policy") }
 guard,err:=bunnyguard.New(policyPath)
 if err!=nil { return Errorf("invalid BunnyGuard manifest: %v",err) }
 if len(in.Args)>512*1024 { return Errorf("signed authorization bundle exceeds 512 KiB input limit") }
 var input struct {
  Plan bunnyauthz.Plan `json:"plan"`
  OwnerBundle bunnyreceipt.Bundle `json:"owner_bundle"`
  CrossUserBundle bunnyreceipt.Bundle `json:"cross_user_bundle"`
 }
 dec:=json.NewDecoder(bytes.NewReader(in.Args)); dec.DisallowUnknownFields()
 if err:=dec.Decode(&input);err!=nil { return Errorf("invalid signed authorization input: %v",err) }
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF { return Errorf("signed authorization input must contain one JSON object") }
 if input.Plan.EngagementID!=guard.Manifest().EngagementID { return Errorf("signed authorization plan is not bound to this engagement") }
 if err:=bunnyauthz.Validate(input.Plan);err!=nil { return Errorf("authorization plan must target a numeric loopback lab origin: %v",err) }
 publicFile:=strings.TrimSpace(os.Getenv(receiptPublicKeyFileEnv))
 if publicFile==""||!filepath.IsAbs(publicFile) { return Errorf("pinned recorder public-key file needs an absolute path") }
 raw,err:=os.ReadFile(publicFile)
 if err!=nil { return Errorf("cannot load pinned public key: %v",err) }
 key,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
 if err!=nil||len(key)!=ed25519.PublicKeySize { return Errorf("invalid pinned Ed25519 public key") }
 result,err:=bunnyauthz.Assess(ed25519.PublicKey(key),input.Plan,bunnyauthz.Capture{
  OwnerBundle:input.OwnerBundle,CrossUserBundle:input.CrossUserBundle,
 })
 if err!=nil { return Errorf("signed cross-user assessment failed: %v",err) }
 b,err:=bunnyauthz.SummaryJSON(result)
 if err!=nil { return Errorf("cannot encode authorization assessment: %v",err) }
 return Text(string(b))
}
