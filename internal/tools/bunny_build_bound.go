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

// compareBuildBoundFixTool can verify signed artifact measurements and HTTP
// observations. It cannot read or modify local application binaries.
type compareBuildBoundFixTool struct{}
func (compareBuildBoundFixTool) Name()string{return "compare_build_bound_fix"}
func (compareBuildBoundFixTool) Description()string{
 return "Verify before/after synthetic authorization receipts against two "+
 "Ed25519-signed measurements of distinct local artifact files. "+
 "Confirms recorder-signed file-byte fingerprints, NOT which code ran on "+
 "the test server or whether a real production fix was deployed. Offline only."
}
func (compareBuildBoundFixTool) RequiresApproval()bool{return false}
func (compareBuildBoundFixTool) UntrustedOutput()bool{return true}
func (compareBuildBoundFixTool) Schema()map[string]any{
 return schema(map[string]any{
  "pair":map[string]any{"type":"object","description":"Two complete signed local owner/foreign/anonymous authorization runs."},
  "before_build":map[string]any{"type":"object","description":"Recorder-signed measurement of the first local artifact file."},
  "after_build":map[string]any{"type":"object","description":"Recorder-signed measurement of the second local artifact file."},
 },"pair","before_build","after_build")
}
func (compareBuildBoundFixTool) Execute(_ context.Context,in Input)Result{
 if strings.TrimSpace(in.SessionID)==""{return Errorf("build-bound remediation comparison requires a session")}
 if len(in.Args)==0||len(in.Args)>1024*1024{return Errorf("build-bound input must be 1..1048576 bytes")}
 manifest:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if manifest==""{return Errorf("build-bound comparison requires a BunnyGuard engagement")}
 guard,err:=bunnyguard.New(manifest)
 if err!=nil{return Errorf("invalid BunnyGuard manifest: %v",err)}
 var request bunnyfix.BuildBoundPair
 d:=json.NewDecoder(bytes.NewReader(in.Args));d.DisallowUnknownFields()
 if err:=d.Decode(&request);err!=nil{return Errorf("invalid build-bound input: %v",err)}
 var extra any
 if err:=d.Decode(&extra);err!=io.EOF{return Errorf("only one JSON request object permitted")}
 engagement:=guard.Manifest().EngagementID
 if request.Pair.BeforePlan.EngagementID!=engagement||request.Pair.AfterPlan.EngagementID!=engagement{
  return Errorf("signed build evidence is outside the active engagement")
 }
 keyFile:=strings.TrimSpace(os.Getenv(receiptPublicKeyFileEnv))
 if !filepath.IsAbs(keyFile){return Errorf("pinned recorder public key must be an absolute path")}
 b,err:=os.ReadFile(keyFile)
 if err!=nil{return Errorf("pinned recorder public key unreadable: %v",err)}
 if len(b)>4096{return Errorf("pinned recorder public key exceeds size limit")}
 key,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(b)))
 if err!=nil||len(key)!=ed25519.PublicKeySize{return Errorf("invalid pinned Ed25519 public key")}
 result,err:=bunnyfix.CompareBuildBound(ed25519.PublicKey(key),request)
 if err!=nil{return Errorf("build-bound receipt comparison rejected: %v",err)}
 output,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return Errorf("build-bound result serialization failed: %v",err)}
 return Text(string(output))
}
