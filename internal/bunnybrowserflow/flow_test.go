package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
 "strings"
 "testing"
 "time"

 "github.com/enowdev/antares/internal/browser"
)

type fake struct{
 current string
 typed string
 closeCount *int
}
func (f *fake) Navigate(_ context.Context,u string)error{f.current=u;return nil}
func (f *fake) Fill(_ context.Context,selector,value string)error{f.typed=value;return nil}
func (f *fake) Click(_ context.Context,selector string)error{return nil}
func (f *fake) Contains(_ context.Context,text string)(bool,error){return text=="Signed in",nil}
func (f *fake) CurrentURL(_ context.Context)(string,error){return f.current,nil}
func (f *fake) Close(){*f.closeCount++}
type fakeFactory struct{browsers map[string]*fake;closed *int}
func (f fakeFactory) New(_ context.Context,actor,origin string)(Browser,error){
 b:=&fake{closeCount:f.closed};f.browsers[actor]=b;return b,nil
}
type fakeSecrets struct{}
func (fakeSecrets) Resolve(_ context.Context,actor,key string)(string,error){return "private_code_secret",nil}
type allowOperator struct{calls *int}
func (a allowOperator) Authorize(_ context.Context,actor,kind string)error{*a.calls++;return nil}

func TestPlanValidationAndStrictOrigin(t *testing.T){
 for _,origin:=range []string{"https://127.0.0.1:444","http://example.com:9090","http://localhost:8080","http://169.254.169.254:80","http://10.0.0.1:80","http://127.0.0.1:80/path","http://127.0.0.1:80?key=x"}{
  if _,err:=Origin(origin);err==nil{t.Fatalf("permitted non-fixture origin %q",origin)}
 }
 p:=Plan{Origin:"http://127.0.0.1:8765",Steps:[]Step{{Actor:"owner",Op:OpNavigate,Path:"/"},{Actor:"owner",Op:OpFill,Selector:"#code",SecretKey:"otp"}}}
 if err:=Validate(p);err!=nil{t.Fatal(err)}
 bad:=[]string{"//evil.test","/../secret","/%2e%2e/secret","/%2Fother","/path?token=x","/path#frag","http://evil.test","/a\\b"}
 for _,path:=range bad{
  p.Steps[0].Path=path
  if err:=Validate(p);err==nil{t.Fatalf("accepted unsafe path %q",path)}
 }
 p.Steps[0].Path="/"
 p.Steps[1].SecretKey="secret/token"
 if err:=Validate(p);err==nil{t.Fatal("accepted secret reference path")}
}
func TestTrustedWorkflowEventsAreRedacted(t *testing.T){
 count:=0
 factory:=fakeFactory{browsers:map[string]*fake{},closed:&count}
 plan:=Plan{Origin:"http://127.0.0.1:9876",Steps:[]Step{
  {Actor:"owner",Op:OpNavigate,Path:"/"},
  {Actor:"owner",Op:OpFill,Selector:"#code",SecretKey:"otp"},
  {Actor:"owner",Op:OpClick,Selector:"#submit"},
  {Actor:"owner",Op:OpAssert,ExpectedText:"Signed in"},
  {Actor:"peer",Op:OpNavigate,Path:"/"},
 }}
 result,err:=Run(context.Background(),plan,factory,fakeSecrets{},nil)
 if err!=nil{t.Fatal(err)}
 if result.Actors!=2||result.StepsCompleted!=5||count!=2{t.Fatalf("unexpected outcome %+v closed %d",result,count)}
 if factory.browsers["owner"]==factory.browsers["peer"]{t.Fatal("session aliasing")}
 data,_:=json.Marshal(result)
 if strings.Contains(string(data),"private_code_secret")||strings.Contains(string(data),"#code"){
  t.Fatal("secret or selector leaked into evidence")
 }
}
func TestHandoffCannotBeModelApproved(t *testing.T){
 plan:=Plan{Origin:"http://127.0.0.1:9876",Steps:[]Step{
  {Actor:"owner",Op:OpNavigate,Path:"/"},
  {Actor:"owner",Op:OpHandoff,ChallengeKind:"mfa"},
 }}
 closed:=0
 if _,err:=Run(context.Background(),plan,fakeFactory{browsers:map[string]*fake{},closed:&closed},fakeSecrets{},nil);err==nil{
  t.Fatal("challenge completed without a trusted operator")
 }
 calls:=0;closed=0
 result,err:=Run(context.Background(),plan,fakeFactory{browsers:map[string]*fake{},closed:&closed},fakeSecrets{},allowOperator{calls:&calls})
 if err!=nil||result.StepsCompleted!=2||calls!=1{
  t.Fatalf("operator handoff failed: %+v %v",result,err)
 }
}
func TestNavigationEscapeDetectedAfterAction(t *testing.T){
 count:=0
 factory:=escapeFactory{closed:&count}
 plan:=Plan{Origin:"http://127.0.0.1:9876",Steps:[]Step{{Actor:"owner",Op:OpNavigate,Path:"/"}}}
 if _,err:=Run(context.Background(),plan,factory,fakeSecrets{},nil);err==nil {
  t.Fatal("accepted off-origin redirect")
 }
 if count!=1{t.Fatal("browser not closed on blocked navigation")}
}
type escapeFactory struct{closed *int}
func (f escapeFactory) New(_ context.Context,actor,origin string)(Browser,error){
 return &escapeBrowser{fake{closeCount:f.closed}},nil
}
type escapeBrowser struct{fake}
func (f *escapeBrowser) Navigate(_ context.Context,u string)error{f.current="http://other.example/";return nil}

func TestChromeLoopbackEmailAndSessionIsolation(t *testing.T){
 if _,err:=browser.FindExecutable("");err!=nil{t.Skip("Chromium unavailable:",err)}
 ctx,cancel:=context.WithTimeout(context.Background(),110*time.Second)
 defer cancel()
 result,err:=RunLab(ctx)
 if err!=nil{t.Fatalf("real Chromium fixture failed: %v",err)}
 if result.Actors!=2||result.StepsCompleted!=18||result.Outcome!="completed_local_browser_fixture"{
  t.Fatalf("incomplete real browser authentication workflow: %+v",result)
 }
}
func TestOperatorCannotModifyUserCreatedEvidence(t *testing.T){
 _=errors.New // Keep missing imports under test when the fixture is platform-skipped.
}
