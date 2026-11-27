package tools

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnytimeline"
)

const (
 scopeEnv="BUNNY_APPROVED_BROWSER_SCOPE"
 planEnv="BUNNY_APPROVED_BROWSER_PLAN"
)
type approvedBrowserAuthTool struct{}
func (approvedBrowserAuthTool) Name()string{return "approved_browser_auth"}
func (approvedBrowserAuthTool) Description()string{
 return "Execute only the local operator's preconfigured BunnyGuard-authorized HTTPS "+
 "browser-authentication plan against explicitly approved external origins, "+
 "using isolated Chromium test identities and OS-keyring secrets. "+
 "No target URL, exploit payload, credential, or plan is accepted from model "+
 "arguments. Requires BUNNY_APPROVED_BROWSER_SCOPE and BUNNY_APPROVED_BROWSER_PLAN "+
 "to reference trusted local files; POST paths and request budgets are scope-enforced. "+
 "MFA/passkey/anti-bot workflows require a genuine operator handoff."
}
func (approvedBrowserAuthTool) Schema()map[string]any{return schema(map[string]any{})}
// Operator-provisioned local policy already grants a bounded workflow.
// GateFromEnv independently checks that a valid BunnyGuard manifest exists.
func (approvedBrowserAuthTool) RequiresApproval()bool{return false}
type trustedHandoff struct{ask AskFunc}
func (a trustedHandoff) Authorize(ctx context.Context,actor,kind string)error{
 if a.ask==nil{return errors.New("interactive operator unavailable")}
 answer,err:=a.ask(ctx,[]AskQuestion{{
  Header:"Test-account verification",
  Question:"Complete the "+kind+" challenge for test persona "+actor+" in the open, authorized browser. Reply APPROVE only when you have finished it yourself.",
  Options:[]string{"APPROVE","CANCEL"},
 }})
 if err!=nil||strings.TrimSpace(answer)!="APPROVE"{return errors.New("operator did not approve challenge")}
 return nil
}
func (approvedBrowserAuthTool) Execute(ctx context.Context,in Input)Result{
 if len(in.Args)>0&&string(in.Args)!="{}"{return Errorf("approved external auth accepts no model-supplied arguments")}
 guardPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 scopePath:=strings.TrimSpace(os.Getenv(scopeEnv))
 planPath:=strings.TrimSpace(os.Getenv(planEnv))
 if guardPath==""||scopePath==""||planPath==""{
  return Errorf("external authentication requires preconfigured BunnyGuard, scope and workflow files")
 }
 scope,plan,err:=bunnybrowserflow.LoadApprovedConfiguration(scopePath,planPath,guardPath)
 if err!=nil{return Errorf("approved external auth configuration rejected: %v",err)}
 guard,err:=bunnyguard.New(guardPath)
 if err!=nil{return Errorf("external engagement manifest invalid")}
 result,err:=bunnybrowserflow.RunConfiguredApproved(ctx,scope,plan,bunnybrowserflow.KeyringSecrets{},
  trustedHandoff{ask:in.AskUser},guard.Manifest(),false)
 if err!=nil{return Errorf("approved external browser flow could not complete: %v",err)}
 data,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return Errorf("browser result encoding failed")}
 out:=Text(string(data))
 if in.SessionID!=""{
  digest:=sha256.Sum256(data)
  _,err=timelineStore().Append(in.SessionID,bunnytimeline.Entry{
   Lane:"auth",Action:"sign_in",State:"succeeded",Source:bunnytimeline.SourceTool,
   AssetID:"approved_"+hex.EncodeToString(digest[:8]),
   EvidenceSHA256:hex.EncodeToString(digest[:]),
  })
  if err!=nil{out.Meta=map[string]any{"timeline_warning":"browser run completed but metadata journal failed"}}
 }
 return out
}
