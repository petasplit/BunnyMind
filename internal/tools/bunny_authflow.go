package tools

import (
 "context"
 "encoding/json"

 "github.com/enowdev/antares/internal/bunnyauthflow"
)

// authWorkflowLabTool performs the entire signup/OTP/login/session flow
// against a server that this tool starts itself on numeric loopback only.
// No external address, mailbox, CAPTCHA or credentials are accepted.
type authWorkflowLabTool struct{}
func (authWorkflowLabTool) Name() string { return "auth_workflow_lab" }
func (authWorkflowLabTool) Description() string {
 return "Run an isolated localhost-only synthetic application that creates two "+
  "test email accounts, reads private in-memory OTP messages, enters codes, "+
  "establishes and rotates bearer sessions, checks logout/replay protections, "+
  "then compares owner, foreign and anonymous resource access. "+
  "Accepts NO target URL or real email addresses. Provides evidence of "+
  "the local workflow only, not a vulnerability on an outside service."
}
func (authWorkflowLabTool) RequiresApproval() bool { return false }
func (authWorkflowLabTool) Schema()map[string]any{
 return schema(map[string]any{
  "deliberate_exposure":map[string]any{
   "type":"boolean","description":"If true, run a second intentionally insecure local fixture that permits cross-user resource access; false tests secure behavior.",
   "default":false,
  },
 })
}
func (authWorkflowLabTool) Execute(ctx context.Context,in Input)Result{
 var args struct{DeliberateExposure bool `json:"deliberate_exposure"`}
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid synthetic auth workflow options: %v",err)}
 result,err:=bunnyauthflow.Run(ctx,args.DeliberateExposure)
 if err!=nil{return Errorf("isolated authentication workflow failed: %v",err)}
 b,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return Errorf("cannot encode synthetic auth workflow: %v",err)}
 return Text(string(b))
}
