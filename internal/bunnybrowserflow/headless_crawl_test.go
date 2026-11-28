package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/browser"
)

type fakeHeadlessDriver struct{
 current string
 visited []string
}
func (f *fakeHeadlessDriver) Navigate(_ context.Context,url string)error{
 f.current=url
 f.visited=append(f.visited,url)
 return nil
}
func (f *fakeHeadlessDriver) URL(_ context.Context)(string,error){return f.current,nil}
func (f *fakeHeadlessDriver) Eval(_ context.Context,_ string)(json.RawMessage,error){
 if f.current=="https://app.example/dashboard"{
  d:=BrowserDiscovery{
   Links:[]string{"https://app.example/docs?token=private","https://app.example/logout",
    "https://offscope.example/admin","https://app.example/docs"},
   ScriptURLs:[]string{"https://app.example/assets/client.js"},
   InlineScripts:[]string{`fetch("/api/profile"); axios.get("/api/v1/accounts"); fetch("https://offscope.example/secret")`},
   ObservedResources:[]string{"https://app.example/api/owner?key=private"},
  }
  raw,_:=json.Marshal(d);return raw,nil
 }
 raw,_:=json.Marshal(BrowserDiscovery{})
 return raw,nil
}
func (f *fakeHeadlessDriver) DrainNetwork(_ context.Context)[]browser.NetworkRequest{
 if strings.HasSuffix(f.current,"/dashboard"){
  return []browser.NetworkRequest{
   {RequestID:"1",ResourceType:"Fetch",Method:"GET",URL:"https://app.example/api/owner?secret=abc",
     Response:&browser.NetworkResponse{Status:200,MIMEType:"application/json"}},
   {RequestID:"2",ResourceType:"Script",Method:"GET",URL:"https://app.example/assets/client.js",
     Response:&browser.NetworkResponse{Status:200,MIMEType:"application/javascript"}},
  }
 }
 return nil
}
func (f *fakeHeadlessDriver) ResponseBody(_ context.Context,id string)(string,string,error){
 if id=="2"{return `fetch('/api/from-bundle'); window.appConfig={endpoint:"/graphql/v1"};`,"application/javascript",nil}
 return "", "",errors.New("not available")
}
func TestHeadlessCrawlUsesSameAuthenticatedBrowserWithoutMutations(t *testing.T){
 driver:=&fakeHeadlessDriver{}
 report,err:=crawlRendered(context.Background(),driver,HeadlessCrawlConfig{
  Origin:"https://app.example",StartPath:"/dashboard",MaxPages:2,MaxDepth:1,
 },nil)
 if err!=nil{t.Fatal(err)}
 if len(driver.visited)!=2||driver.visited[0]!="https://app.example/dashboard"||
  driver.visited[1]!="https://app.example/docs"{t.Fatalf("wrong navigation %#v",driver.visited)}
 if report.StopReason!="max_pages"||len(report.Pages)!=2{
  t.Fatalf("wrong scan outcome %+v",report)
 }
 if report.Pages[0].ScriptBodiesInspected!=1{t.Fatalf("script not parsed %+v",report.Pages)}
 joined,_:=json.Marshal(report)
 for _,token:=range []string{"?secret=","?key=","private","offscope.example","/logout"}{
  if strings.Contains(string(joined),token){t.Fatalf("sensitive/out-of-scope data leaked: %s",token)}
 }
 for _,expected:=range []string{"/api/profile","/api/v1/accounts","/api/from-bundle","/graphql/v1"}{
  if !strings.Contains(string(joined),expected){t.Fatalf("missed JS endpoint %s",expected)}
 }
}
func TestDiscoveryRejectsOutOfScopeAndMutatingLinks(t *testing.T){
 origin:="https://app.example"
 for _,raw:=range []string{
  "http://app.example/api","https://app.example.evil.test/api",
  "https://app.example/delete","https://app.example/logout",
  "https://app.example/assets/%2fadmin","javascript:alert(1)","https://app.example:8443/path",
 }{
  if _,ok:=safeDiscoveryPath(origin,raw);ok{t.Fatalf("unsafe link %s accepted",raw)}
 }
 if v,ok:=safeDiscoveryPath(origin,"https://app.example/api/items?token=secret#part");!ok||v!="https://app.example/api/items"{
  t.Fatalf("failed to strip token/query: %s %v",v,ok)
 }
}
func TestHeadlessConfigFailClosed(t *testing.T){
 manifest:=approvedManifest()
 scope:=sampleScope()
 plan:=Plan{Origin:"https://app.example",Steps:[]Step{
  {Actor:"owner",Op:OpNavigate,Path:"/login"},
  {Actor:"owner",Op:OpFill,Selector:"#username",SecretKey:"email"},
  {Actor:"owner",Op:OpClick,Selector:"#submit"},
  {Actor:"owner",Op:OpAssert,ExpectedText:"Signed in"},
 }}
 good:=HeadlessCrawlConfig{Origin:"https://app.example",StartPath:"/dashboard",MaxPages:2,MaxDepth:1}
 if err:=ValidateHeadlessConfig(good,plan,scope,manifest);err!=nil{t.Fatal(err)}
 bad:=good;bad.Origin="https://unlisted.example"
 if err:=ValidateHeadlessConfig(bad,plan,scope,manifest);err==nil{t.Fatal("offscope crawl allowed")}
 bad=good;bad.MaxPages=90
 if err:=ValidateHeadlessConfig(bad,plan,scope,manifest);err==nil{t.Fatal("unbounded crawl allowed")}
 badPlan:=plan
 badPlan.Steps=append([]Step(nil),plan.Steps...)
 badPlan.Steps=append(badPlan.Steps,Step{Actor:"owner",Op:OpHandoff,ChallengeKind:"anti_bot"})
 if err:=ValidateHeadlessConfig(good,badPlan,scope,manifest);err==nil{t.Fatal("unapproved challenge in headless flow allowed")}
 badPlan=plan
 badPlan.Steps=append([]Step(nil),plan.Steps[:len(plan.Steps)-1]...)
 if err:=ValidateHeadlessConfig(good,badPlan,scope,manifest);err==nil{t.Fatal("login without final assertion allowed")}
}
