package tools

import (
 "context"
 "encoding/json"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/findings"
)
func TestFindingFocusGroundedRedactedAndSessionScoped(t *testing.T){
 ledger:=findings.NewStore(t.TempDir())
 _,err:=ledger.Add("engage-A",findings.Finding{
  Title:"Private test issue",Severity:findings.High,
  Reproduce:"POST /private?token=private-secret",PoC:"Bearer secret-session-value",
  Impact:"Test-only access",Remediation:"Change owner check",
 })
 if err!=nil{t.Fatal(err)}
 tool:=findingFocusTool{}
 call:=func(session,action,q string)Result{
  args,_:=json.Marshal(map[string]any{"finding_id":"F-001","action":action,"question":q})
  return tool.Execute(context.Background(),Input{SessionID:session,Args:args,Deps:&Deps{Findings:ledger}})
 }
 for _,action:=range []string{"inspect","ask","retest","remediation"}{
  out:=call("engage-A",action,"how serious is this?")
  if out.IsError{t.Fatalf("action %s failed: %s",action,out.Content)}
  for _,secret:=range []string{"private-secret","secret-session-value","/private?token=","Test-only access"}{
   if strings.Contains(out.Content,secret){t.Fatalf("raw sensitive ledger content leaked: %s",secret)}
  }
  if !strings.Contains(out.Content,"F-001")||!strings.Contains(out.Content,"evidence_reference_sha256"){
   t.Fatalf("missing grounded finding provenance: %s",out.Content)
  }
 }
 if out:=call("engage-B","inspect","");!out.IsError{t.Fatal("cross-session finding was returned")}
}
