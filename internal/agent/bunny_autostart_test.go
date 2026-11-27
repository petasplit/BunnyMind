package agent

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/llm"
)
func readyPolicy(t *testing.T){
 t.Helper()
 path:=filepath.Join(t.TempDir(),"engagement.json")
 p:=bunnyguard.Policy{
  EngagementID:"synthetic_scope",AllowedOrigins:[]string{"https://app.example.test"},
  AllowedMethods:[]string{"GET","HEAD"},MaxNetworkCalls:8,
 }
 raw,err:=json.Marshal(p);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 t.Setenv(bunnyguard.EnvPolicy,path)
}
func TestSecurityToolFirstStartsFromAuthorizedURL(t *testing.T){
 readyPolicy(t)
 req:=Request{Message:"Authorized bug bounty, scope https://app.example.test/accounts. Inspect URL and record observations."}
 if !readySecurityMission(req){t.Fatal("authorized scope did not activate")}
 autoSelectSecurityRole(&req)
 if req.Role!="security"{t.Fatalf("role=%q",req.Role)}
 if !toolFirstMission(req,[]llm.Tool{{Name:"scoped_read"}}){t.Fatal("tool-first did not activate")}
}
func TestOutOfScopeURLCannotActivate(t *testing.T){
 readyPolicy(t)
 req:=Request{Role:"security",Message:"Test https://external.example.org/login under the current scope."}
 if readySecurityMission(req){t.Fatal("external URL activated")}
}
func TestNoManifestOrReaderNoForcedTools(t *testing.T){
 readyPolicy(t)
 req:=Request{Role:"security",Message:"Inspect https://app.example.test"}
 if toolFirstMission(req,nil){t.Fatal("forced tool with no reader")}
 t.Setenv(bunnyguard.EnvPolicy,"")
 if readySecurityMission(req){t.Fatal("missing manifest allowed rapid start")}
}
func TestNormalConversationsDoNotAutoSelect(t *testing.T){
 readyPolicy(t)
 req:=Request{Message:"What does https://app.example.test do?"}
 autoSelectSecurityRole(&req)
 if req.Role!=""{t.Fatal("unrelated web request became a security engagement")}
}
func TestSecurityURLMatchingIsStrict(t *testing.T){
 origins:=[]string{"https://app.example.test"}
 for _,message:=range []string{
  "https://evil.example.test/path","http://app.example.test",
  "https://app.example.test.evil.org/path","https://user:pw@app.example.test/path",
 }{
  if authorizedSecurityURL(message,origins){t.Fatalf("wrong origin accepted: %s",message)}
 }
 if !authorizedSecurityURL("Asset: https://app.example.test/a?q=3).",origins){t.Fatal("allowed nested URL rejected")}
}
func TestOnlyRealToolNamesReceiveProgress(t *testing.T){
 if securityActionStatus("scoped_read")!="Inspecting in-scope URL"{t.Fatal("missing read status")}
 if securityActionStatus("auth_workflow_lab")!="Testing synthetic sign-in"{t.Fatal("synthetic sign-in label")}
 if strings.Contains(strings.ToLower(securityActionStatus("auth_workflow_lab")),"target"){t.Fatal("misleading target sign-in label")}
 if securityActionStatus("http_request")!=""||securityActionStatus("terminal")!=""{t.Fatal("legacy network shortcut labelled as progress")}
}

func TestFirstSecurityProviderChoice(t *testing.T){
 if got:=firstSecurityToolChoice(true);got!="required"{t.Fatalf("expected tool-first policy: %q",got)}
 if got:=firstSecurityToolChoice(false);got!=""{t.Fatalf("ordinary chat should not force tool use: %q",got)}
}
func TestSpecialistNeverRunsUserAutoMission(t *testing.T){
 readyPolicy(t)
 req:=Request{Role:"security-recon",Depth:1,Quiet:true,Message:"Scope https://app.example.test"}
 if readySecurityMission(req){t.Fatal("subagent silently reselected top-level mission")}
}
func TestSecurityScopeManifestInvalidFailsClosed(t *testing.T){
 readyPolicy(t)
 t.Setenv(bunnyguard.EnvPolicy,filepath.Join(t.TempDir(),"missing.json"))
 req:=Request{Role:"security",Message:"Scope https://app.example.test"}
 if readySecurityMission(req){t.Fatal("missing approved manifest activated")}
}
