package tools

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnytimeline"
)

const (
 headlessCrawlEnv="BUNNY_HEADLESS_CRAWL_CONFIG"
 headlessScopeEnv="BUNNY_HEADLESS_BROWSER_SCOPE"
 headlessLoginEnv="BUNNY_HEADLESS_LOGIN_PLAN"
)
type approvedHeadlessCrawlTool struct{}
func (approvedHeadlessCrawlTool) Name()string{return "approved_headless_crawl"}
func (approvedHeadlessCrawlTool) Description()string{
 return "Use a separately configured, exact-origin HTTPS test-account login "+
  "in a fresh isolated headless Chromium, then switch its request gate "+
  "irrevocably to GET/HEAD-only and inventory rendered DOM links, JavaScript "+
  "endpoint references, and observed API requests. Evidence is privately "+
  "encrypted, time-bounded and query-secret-redacted. Operator-provisioned "+
  "BunnyGuard, browser scope, login plan, evidence vault and keyring secrets "+
  "are mandatory; this model tool accepts ZERO URLs, credentials or steps."
}
func (approvedHeadlessCrawlTool) Schema()map[string]any{return schema(map[string]any{})}
func (approvedHeadlessCrawlTool) RequiresApproval()bool{return false}
func (approvedHeadlessCrawlTool) Execute(ctx context.Context,in Input)Result{
 if len(in.Args)>0&&strings.TrimSpace(string(in.Args))!="{}"{
  return Errorf("headless crawl accepts no model-proposed target or login action")
 }
 guard:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 scope:=strings.TrimSpace(os.Getenv(headlessScopeEnv))
 login:=strings.TrimSpace(os.Getenv(headlessLoginEnv))
 spec:=strings.TrimSpace(os.Getenv(headlessCrawlEnv))
 out:=strings.TrimSpace(os.Getenv("BUNNY_PROOF_OUTPUT"))
 if guard==""||scope==""||login==""||spec==""||out==""{
  return Errorf("approved headless crawl is not provisioned by operator-owned guard, scope, login, configuration and evidence paths")
 }
 s,p,c,manifest,err:=bunnybrowserflow.LoadHeadlessConfiguration(guard,scope,login,spec)
 if err!=nil{return Errorf("headless crawl scope validation failed: %v",err)}
 if in.Emit!=nil{in.Emit(Progress{Tool:"approved_headless_crawl",Message:"Signing into approved test-account browser"})}
 report,err:=bunnybrowserflow.RunConfiguredHeadlessCrawl(ctx,s,p,c,manifest,out)
 if err!=nil{return Errorf("headless crawl did not complete: %v",err)}
 if in.Emit!=nil{in.Emit(Progress{Tool:"approved_headless_crawl",Message:"Indexed JavaScript endpoints and saved encrypted browser evidence"})}
 raw,err:=json.MarshalIndent(report,"","  ")
 if err!=nil{return Errorf("headless report could not be encoded")}
 result:=Text(string(raw))
 if in.SessionID!=""{
  d:=sha256.Sum256(raw)
  _,err=timelineStore().Append(in.SessionID,bunnytimeline.Entry{
   Lane:"exploration",Action:"map",State:"succeeded",Source:bunnytimeline.SourceTool,
   AssetID:"headless_"+hex.EncodeToString(d[:8]),EvidenceSHA256:hex.EncodeToString(d[:]),
  })
  if err!=nil{result.Meta=map[string]any{"timeline_warning":"headless results saved but activity journal failed"}}
 }
 return result
}
