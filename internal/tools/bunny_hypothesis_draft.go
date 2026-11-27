package tools

import (
 "context"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyautoprobe"
 "github.com/enowdev/antares/internal/bunnyguard"
)
// hypothesisDraftTool is a low-risk AI planning surface. The model may select
// an evidence hypothesis and index but cannot supply Python instructions,
// arbitrary URLs, credentials, command strings or resource identifiers.
type hypothesisDraftTool struct{}
func (hypothesisDraftTool) Name()string{return "python_hypothesis_draft"}
func (hypothesisDraftTool) Description()string{
 return "Draft a reproducible Python security hypothesis using ONLY indexed "+
 "test-owned candidate/control endpoints already approved in the local "+
 "BUNNY_ADAPTIVE_PROOF_SPEC inventory. The model chooses a safe semantic theme "+
 "and two array indices, and a trusted compiler emits exact scenario.py and "+
 "an independent offline oracle.py. No network requests are executed. "+
 "Drafts have SHA-256 provenance and do not establish vulnerability impact."
}
func (hypothesisDraftTool) RequiresApproval()bool{return false}
func (hypothesisDraftTool) Schema()map[string]any{
 return schema(map[string]any{
  "theme":propEnum("Non-destructive test hypothesis.","authorization_boundary","session_boundary","input_consistency","status_differential","marker_provenance"),
  "candidate_index":map[string]any{"type":"integer","minimum":0,"maximum":11,"description":"Index into separately approved candidate paths."},
  "control_index":map[string]any{"type":"integer","minimum":0,"maximum":11,"description":"Index into separately approved negative control paths."},
 },"theme","candidate_index","control_index")
}
func (hypothesisDraftTool) Execute(_ context.Context,in Input)Result{
 var idea bunnyautoprobe.Idea
 if err:=in.Bind(&idea);err!=nil{return Errorf("invalid structured Python hypothesis")}
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 specPath:=strings.TrimSpace(os.Getenv(adaptiveProofSpecEnv))
 root:=strings.TrimSpace(os.Getenv(proofRootEnv))
 if policyPath==""||specPath==""||root==""{
  return Errorf("operator-approved BunnyGuard, endpoint inventory and evidence output path required")
 }
 guard,err:=bunnyguard.New(policyPath)
 if err!=nil{return Errorf("invalid authorized engagement manifest")}
 raw,err:=os.ReadFile(specPath)
 if err!=nil{return Errorf("trusted candidate inventory unavailable")}
 spec,err:=bunnyautoprobe.Load(raw,guard.Manifest())
 if err!=nil{return Errorf("candidate inventory invalid: %v",err)}
 result,err:=bunnyautoprobe.Draft(root,spec,idea,guard.Manifest())
 if err!=nil{return Errorf("safe Python hypothesis rejected: %v",err)}
 output,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return Errorf("cannot serialize draft result")}
 return Text(string(output))
}
