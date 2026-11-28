package tools

import (
 "context"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
)
type approvedBrowserReplayTool struct{}
func (approvedBrowserReplayTool) Name()string{return "approved_browser_replay"}
func (approvedBrowserReplayTool) Description()string{
 return "Reauthenticate twice in two fresh, isolated, operator-approved "+
  "Chromium test-account profiles, compare independent endpoint inventories, "+
  "and save an encrypted replay capsule. Never serializes cookies, tokens, "+
  "or a live browser profile. Requires the same reviewed guard/browser/"+
  "login/crawl config as approved_headless_crawl and the private vault."
}
func (approvedBrowserReplayTool) RequiresApproval()bool{return false}
func (approvedBrowserReplayTool) Schema()map[string]any{return schema(map[string]any{})}
func (approvedBrowserReplayTool) Execute(ctx context.Context,in Input)Result{
 if len(in.Args)>0&&strings.TrimSpace(string(in.Args))!="{}"{return Errorf("replay accepts no model-written browser instructions")}
 guard:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 scope:=strings.TrimSpace(os.Getenv(headlessScopeEnv))
 login:=strings.TrimSpace(os.Getenv(headlessLoginEnv))
 crawl:=strings.TrimSpace(os.Getenv(headlessCrawlEnv))
 out:=strings.TrimSpace(os.Getenv("BUNNY_PROOF_OUTPUT"))
 if guard==""||scope==""||login==""||crawl==""||out==""{
  return Errorf("operator-owned replay configuration is not provisioned")
 }
 s,p,c,manifest,err:=bunnybrowserflow.LoadHeadlessConfiguration(guard,scope,login,crawl)
 if err!=nil{return Errorf("replay configuration rejected: %v",err)}
 if in.Emit!=nil{in.Emit(Progress{Tool:"approved_browser_replay",Message:"Repeating approved login in fresh isolated profiles"})}
 verdict,err:=bunnybrowserflow.ReplayApprovedFreshState(ctx,s,p,c,manifest,out)
 if err!=nil{return Errorf("fresh authenticated replay incomplete: %v",err)}
 raw,err:=json.MarshalIndent(verdict,"","  ")
 if err!=nil{return Errorf("replay verdict serialization failed")}
 return Text(string(raw))
}
