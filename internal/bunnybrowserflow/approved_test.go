package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
)
func approvedManifest() bunnyguard.Policy{
 return bunnyguard.Policy{
  EngagementID:"example-approved-audit",
  AllowedOrigins:[]string{"https://app.example","https://login.example"},
  AllowedMethods:[]string{"GET","HEAD","OPTIONS","POST"},
  MaxNetworkCalls:300,MinIntervalMS:100,
 }
}
func sampleScope() ApprovedScope{
 return ApprovedScope{
  EngagementID:"example-approved-audit",
  AllowedOrigins:[]string{"https://app.example"},
  ApprovedPostPaths:[]string{"/login","/signup"},
  MaxBrowserRequests:120,MaxTunnels:12,MinIntervalMS:150,
 }
}
func TestExternalScopeBoundToBunnyGuard(t *testing.T){
 allowed,err:=ValidateApprovedScope(sampleScope(),approvedManifest())
 if err!=nil||!allowed["https://app.example"]{t.Fatalf("approved scope failed %v %+v",err,allowed)}
 scope:=sampleScope();scope.AllowedOrigins=[]string{"https://unlisted.example"}
 if _,err:=ValidateApprovedScope(scope,approvedManifest());err==nil{t.Fatal("out-of-scope origin permitted")}
 scope=sampleScope();scope.AllowedOrigins=[]string{"https://app.example.evil.test"}
 if _,err:=ValidateApprovedScope(scope,approvedManifest());err==nil{t.Fatal("subdomain confusion")}
 scope=sampleScope();scope.MaxBrowserRequests=301
 if _,err:=ValidateApprovedScope(scope,approvedManifest());err==nil{t.Fatal("budget greater than manifest")}
 scope=sampleScope();scope.MinIntervalMS=99
 if _,err:=ValidateApprovedScope(scope,approvedManifest());err==nil{t.Fatal("weaker rate limit")}
 scope=sampleScope();scope.EngagementID="another-engagement"
 if _,err:=ValidateApprovedScope(scope,approvedManifest());err==nil{t.Fatal("engagement mismatch")}
 manifest:=approvedManifest();manifest.AllowedMethods=[]string{"GET","HEAD"}
 if _,err:=ValidateApprovedScope(sampleScope(),manifest);err==nil{t.Fatal("POST allowed without permission")}
 scope=sampleScope();scope.ApprovedPostPaths=[]string{"/login/../admin"}
 if _,err:=ValidateApprovedScope(scope,approvedManifest());err==nil{t.Fatal("POST traversal allowed")}
}
func TestExternalTrustedBrowserWorkflowAgainstFakeAdapter(t *testing.T){
 closed:=0
 ff:=fakeFactory{browsers:map[string]*fake{},closed:&closed}
 scope:=sampleScope()
 plan:=Plan{Origin:"https://app.example",Steps:[]Step{
  {Actor:"owner",Op:OpNavigate,Path:"/"},
  {Actor:"owner",Op:OpFill,Selector:"#code",SecretKey:"otp"},
  {Actor:"owner",Op:OpAssert,ExpectedText:"Signed in"},
  {Actor:"peer",Op:OpNavigate,Path:"/"},
 }}
 out,err:=RunApproved(context.Background(),plan,scope,ff,fakeSecrets{},nil,approvedManifest())
 if err!=nil{t.Fatal(err)}
 if out.StepsCompleted!=4||out.Actors!=2||out.Outcome!="completed_approved_external_workflow"||closed!=2{
  t.Fatalf("external runner did not reuse isolated persona execution: %+v",out)
 }
 b,_:=json.Marshal(out)
 if strings.Contains(string(b),"private_code_secret"){t.Fatal("secret in result")}
}
func TestApprovedConfigStrictFileLoading(t *testing.T){
 dir:=t.TempDir()
 guardPath:=filepath.Join(dir,"guard.json")
 scopePath:=filepath.Join(dir,"scope.json")
 planPath:=filepath.Join(dir,"plan.json")
 write:=func(path string,v any){
  t.Helper()
  b,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
 }
 write(guardPath,approvedManifest())
 write(scopePath,sampleScope())
 write(planPath,Plan{Origin:"https://app.example",Steps:[]Step{{Actor:"owner",Op:OpNavigate,Path:"/"}}})
 scope,plan,err:=LoadApprovedConfiguration(scopePath,planPath,guardPath)
 if err!=nil||scope.EngagementID!="example-approved-audit"||plan.Origin!="https://app.example"{
  t.Fatalf("config load failed %+v %+v %v",scope,plan,err)
 }
 write(planPath,map[string]any{"origin":"https://app.example","steps":[]any{},"unexpected":true})
 if _,_,err:=LoadApprovedConfiguration(scopePath,planPath,guardPath);err==nil{t.Fatal("unknown config key accepted")}
}
func TestNoModelSelectedTargetOrSecretRef(t *testing.T){
 if ValidSecretRef("owner/email","otp"){t.Fatal("invalid actor path accepted")}
 if ValidSecretRef("owner","../../password"){t.Fatal("secret key traversal accepted")}
 if _,err:=strictOrigin("http://app.example");err==nil{t.Fatal("non-TLS allowed")}
 if _,err:=strictOrigin("https://app.example:8443");err==nil{t.Fatal("unapproved port")}
 if approvedBrowserURL("https://app.example.evil.test/",map[string]bool{"https://app.example":true}){t.Fatal("lookalike origin")}
}
