package tools

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "io"
 "os"
 "path/filepath"
 "strings"

 "github.com/enowdev/antares/internal/bunnyfix"
 "github.com/enowdev/antares/internal/bunnyguard"
)

// compareAuthzFixTool is an offline assessment of signed, local-only
// before/after observations. No network traffic or private signing keys.
type compareAuthzFixTool struct{}
func (compareAuthzFixTool) Name()string{return "compare_authz_fix_receipts"}
func (compareAuthzFixTool) Description()string{
 return "Compare two independently recorded and signed local authorization-lab "+
 "runs for apparent remediation, regression or unchanged behavior. "+
 "Requires a pinned public key and a validated BunnyGuard engagement; "+
 "never runs requests, applies patches or certifies production fixes."
}
func (compareAuthzFixTool) RequiresApproval()bool{return false}
func (compareAuthzFixTool) UntrustedOutput()bool{return true}
func (compareAuthzFixTool) Schema()map[string]any{
 return schema(map[string]any{
  "before_plan":map[string]any{"type":"object","description":"Local first-run engagement/case/marker/URL identifiers."},
  "before_capture":map[string]any{"type":"object","description":"Signed first-run synthetic owner and foreign observations."},
  "after_plan":map[string]any{"type":"object","description":"Local second-run plan, same case and distinct run ID."},
  "after_capture":map[string]any{"type":"object","description":"Signed second-run synthetic owner and foreign observations."},
 },"before_plan","before_capture","after_plan","after_capture")
}
func (compareAuthzFixTool) Execute(_ context.Context,in Input)Result{
 if strings.TrimSpace(in.SessionID)==""{return Errorf("remediation comparison requires a session")}
 if len(in.Args)==0||len(in.Args)>1024*1024{return Errorf("signed comparison input must be 1..1048576 bytes")}
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if policyPath==""{return Errorf("BunnyGuard manifest required")}
 policy,err:=bunnyguard.New(policyPath)
 if err!=nil{return Errorf("invalid engagement manifest: %v",err)}
 var pair bunnyfix.Pair
 decoder:=json.NewDecoder(bytes.NewReader(in.Args))
 decoder.DisallowUnknownFields()
 if err:=decoder.Decode(&pair);err!=nil{return Errorf("invalid signed comparison data: %v",err)}
 var extra any
 if err:=decoder.Decode(&extra);err!=io.EOF{return Errorf("expected one JSON object")}
 if pair.BeforePlan.EngagementID!=policy.Manifest().EngagementID||
 pair.AfterPlan.EngagementID!=policy.Manifest().EngagementID{
  return Errorf("comparison references a different engagement")
 }
 publicPath:=strings.TrimSpace(os.Getenv(receiptPublicKeyFileEnv))
 if !filepath.IsAbs(publicPath){return Errorf("pinned recorder public key must use absolute path")}
 raw,err:=os.ReadFile(publicPath)
 if err!=nil{return Errorf("pinned recorder key unavailable: %v",err)}
 if len(raw)>4096{return Errorf("pinned recorder key exceeds size limit")}
 pub,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
 if err!=nil||len(pub)!=ed25519.PublicKeySize{return Errorf("invalid pinned Ed25519 public key")}
 result,err:=bunnyfix.Compare(ed25519.PublicKey(pub),pair)
 if err!=nil{return Errorf("signed remediation comparison failed: %v",err)}
 data,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return Errorf("cannot format remediation comparison: %v",err)}
 return Text(string(data))
}
