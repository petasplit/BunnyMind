package bunnyguard

import (
 "os"
 "path/filepath"
 "testing"
)
func TestAdaptiveExternalBrowserNeedsOperatorInstalledPolicy(t *testing.T){
 manifest:=filepath.Join(t.TempDir(),"guard.json")
 data:=[]byte(`{"engagement_id":"approved-adaptive-fixture","allowed_origins":["https://app.example"],"allowed_methods":["GET","HEAD","POST"],"max_network_calls":6}`)
 if err:=os.WriteFile(manifest,data,0600);err!=nil{t.Fatal(err)}
 g,err:=New(manifest);if err!=nil{t.Fatal(err)}
 t.Setenv("BUNNY_APPROVED_BROWSER_SCOPE","")
 t.Setenv("BUNNY_APPROVED_ADAPTIVE_CONFIG","")
 if g.Evaluate("session","approved_adaptive_auth","{}").Allowed{t.Fatal("unconfigured adaptive mode allowed")}
 t.Setenv("BUNNY_APPROVED_BROWSER_SCOPE","/trusted/scope.json")
 t.Setenv("BUNNY_APPROVED_ADAPTIVE_CONFIG","/trusted/adaptive.json")
 if g.Evaluate("session","approved_adaptive_auth",`{"url":"https://evil.example"}`).Allowed{
  t.Fatal("model-chosen external target permitted")
 }
 if !g.Evaluate("session","approved_adaptive_auth","{}").Allowed{
  t.Fatal("configured adaptive workflow failed guard")
 }
 if _,err:=VerifyAudit(manifest);err!=nil{t.Fatalf("audit hash chain invalid: %v",err)}
}
