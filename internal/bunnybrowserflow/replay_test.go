package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
)

func replayFixtures()(ApprovedScope,Plan,HeadlessCrawlConfig,bunnyguard.Policy){
 scope:=sampleScope()
 plan:=Plan{Origin:"https://app.example",Steps:[]Step{
  {Actor:"owner",Op:OpNavigate,Path:"/login"},
  {Actor:"owner",Op:OpFill,Selector:"#username",SecretKey:"email"},
  {Actor:"owner",Op:OpClick,Selector:"#submit"},
  {Actor:"owner",Op:OpAssert,ExpectedText:"Signed in"},
 }}
 cfg:=HeadlessCrawlConfig{Origin:"https://app.example",StartPath:"/dashboard",MaxPages:2,MaxDepth:1}
 return scope,plan,cfg,approvedManifest()
}
func fakeHeadlessReport(changed bool)HeadlessReport{
 endpoints:=[]HeadlessEndpoint{{Path:"/api/profile",Method:"GET",Source:"browser_network"}}
 if changed{endpoints[0].Path="/api/changed"}
 return HeadlessReport{
  EngagementID:"example-approved-audit",Origin:"https://app.example",AuthStepsCompleted:4,
  Pages:[]HeadlessPage{{Path:"/dashboard"},{Path:"/docs"}},
  Endpoints:endpoints,EvidenceFile:"private-crawl-file.json",
 }
}
func TestReplayOnlyReauthenticatesNewProfiles(t *testing.T){
 scope,plan,cfg,manifest:=replayFixtures()
 calls:=0
 root:=t.TempDir()
 key:=[]byte(strings.Repeat("R",32))
 outcome,err:=replayWith(context.Background(),scope,plan,cfg,manifest,root,key,
  func(context.Context)(HeadlessReport,error){calls++;return fakeHeadlessReport(false),nil})
 if err!=nil{t.Fatal(err)}
 if calls!=2||outcome.FreshBrowserProfiles!=2||
  outcome.Outcome!="authenticated_inventory_reproduced"||outcome.ImpactVerified{
  t.Fatalf("invalid replay %+v calls %d",outcome,calls)
 }
 dir:=filepath.Join(root,manifest.EngagementID)
 name:=strings.TrimSuffix(outcome.EncryptedCapsule.File,".enc")
 recovered,err:=ReviewReplayCapsule(dir,name,key)
 if err!=nil||recovered.Outcome!=outcome.Outcome{t.Fatalf("replay not independently reopenable: %+v %v",recovered,err)}
 blob,err:=os.ReadFile(filepath.Join(dir,outcome.EncryptedCapsule.File))
 if err!=nil{t.Fatal(err)}
 for _,secret:=range []string{"session_cookie","private session","Signed in","/api/profile"}{
  if strings.Contains(string(blob),secret){t.Fatalf("plaintext sensitive content in capsule: %s",secret)}
 }
}
func TestReplayReportsDivergenceWithoutInventingImpact(t *testing.T){
 scope,plan,cfg,manifest:=replayFixtures()
 run:=0
 outcome,err:=replayWith(context.Background(),scope,plan,cfg,manifest,t.TempDir(),
  []byte(strings.Repeat("R",32)),func(context.Context)(HeadlessReport,error){
   run++
   return fakeHeadlessReport(run==2),nil
  })
 if err!=nil{t.Fatal(err)}
 if outcome.Outcome!="authenticated_state_diverged"||outcome.ImpactVerified||outcome.FirstFingerprint==outcome.SecondFingerprint{
  t.Fatalf("bad evidence comparison %+v",outcome)
 }
 data,_:=json.Marshal(outcome)
 if strings.Contains(string(data),"password")||strings.Contains(string(data),"session_cookie"){
  t.Fatal("credential field in replay result")
 }
}
func TestReplayStopsOnFailedAuthentication(t *testing.T){
 scope,plan,cfg,manifest:=replayFixtures()
 count:=0
 _,err:=replayWith(context.Background(),scope,plan,cfg,manifest,t.TempDir(),
  []byte(strings.Repeat("R",32)),func(context.Context)(HeadlessReport,error){
   count++;return HeadlessReport{},errors.New("signed-in assertion failed")
  })
 if err==nil||count!=1{t.Fatalf("replay did not fail closed: %d %v",count,err)}
}
func TestReplayRequiresAggregateBudget(t *testing.T){
 scope,plan,cfg,manifest:=replayFixtures()
 manifest.MaxNetworkCalls=180
 if _,err:=replayWith(context.Background(),scope,plan,cfg,manifest,t.TempDir(),
  []byte(strings.Repeat("R",32)),func(context.Context)(HeadlessReport,error){return fakeHeadlessReport(false),nil});err==nil{
  t.Fatal("two browser profiles exceeded aggregate budget")
 }
}
