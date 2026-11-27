package bunnyguard

import (
 "os"
 "path/filepath"
 "testing"
)
func TestApprovedExternalBrowserNeedsTrustedSetup(t *testing.T){
 p:=filepath.Join(t.TempDir(),"manifest.json")
 data:=[]byte(`{"engagement_id":"approved-browser-fixture","allowed_origins":["https://staging.example"],"allowed_methods":["GET","HEAD","POST"],"max_network_calls":4}`)
 if err:=os.WriteFile(p,data,0600);err!=nil{t.Fatal(err)}
 g,err:=New(p);if err!=nil{t.Fatal(err)}
 t.Setenv("BUNNY_APPROVED_BROWSER_SCOPE","")
 t.Setenv("BUNNY_APPROVED_BROWSER_PLAN","")
 if g.Evaluate("scan","approved_browser_auth","{}").Allowed{
  t.Fatal("approved browser allowed without local operator policy")
 }
 t.Setenv("BUNNY_APPROVED_BROWSER_SCOPE","/operator/scope.json")
 t.Setenv("BUNNY_APPROVED_BROWSER_PLAN","/operator/plan.json")
 if g.Evaluate("scan","approved_browser_auth",`{"url":"https://evil.example"}`).Allowed{
  t.Fatal("model-supplied URL unexpectedly permitted")
 }
 if !g.Evaluate("scan","approved_browser_auth","{}").Allowed{
  t.Fatal("trusted plan invocation denied after policy preflight")
 }
 if _,err:=VerifyAudit(p);err!=nil{t.Fatalf("gate audit invalid: %v",err)}
}
