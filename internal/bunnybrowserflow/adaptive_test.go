package bunnybrowserflow

import (
 "context"
 "errors"
 "strings"
 "testing"
 "time"

 "github.com/enowdev/antares/internal/bunnyguard"
)
type adaptiveFakeSecrets struct{used []string}
func (a *adaptiveFakeSecrets) Resolve(_ context.Context,actor,key string)(string,error){
 a.used=append(a.used,actor+":"+key)
 switch key{case "email":return actor+"@example.test",nil;case "username":return actor,nil;case "password":return "private-password-only-in-fake",nil}
 return "",errors.New("unknown secret")
}
type adaptiveOTP struct{armed,w aCount}
type aCount map[string]int
func (o *adaptiveOTP) Arm(_ context.Context,actor string)error{
 if o.armed==nil{o.armed=aCount{}};o.armed[actor]++;return nil
}
func (o *adaptiveOTP) Wait(_ context.Context,actor string)(string,error){
 if o.w==nil{o.w=aCount{}};o.w[actor]++
 return "673921",nil
}
type adaptiveMockBrowser struct{
 page int
 kind string
 current string
 filled []string
 closed *int
 ambiguous bool
 offscope bool
}
func (b *adaptiveMockBrowser) Navigate(_ context.Context,u string)error{
 b.current=u
 if strings.HasSuffix(u,"/signup"){b.page=1}
 return nil
}
func (b *adaptiveMockBrowser) Fill(_ context.Context,selector,value string)error{
 if !safeDiscoverySelector.MatchString(selector){return errors.New("invalid selector")}
 b.filled=append(b.filled,value)
 return nil
}
func (b *adaptiveMockBrowser) Click(_ context.Context,selector string)error{
 if selector!="#bm-auto-submit-1"{return errors.New("unexpected click")}
 b.page++
 if b.offscope{b.current="https://evil.test/"}
 return nil
}
func (b *adaptiveMockBrowser) Contains(_ context.Context,text string)(bool,error){
 return b.page>=b.successAt(),nil
}
func (b *adaptiveMockBrowser) successAt()int{
 if b.kind=="signup"{return 3}
 return 2
}
func (b *adaptiveMockBrowser) CurrentURL(_ context.Context)(string,error){return b.current,nil}
func (b *adaptiveMockBrowser) Close(){*b.closed++}
func (b *adaptiveMockBrowser) DiscoverAuth(_ context.Context)(AuthPageState,error){
 f:=func(role string)DiscoveredField{return DiscoveredField{Selector:"#bm-auto-field-1",Role:role}}
 result:=AuthPageState{Kind:"login",Fields:[]DiscoveredField{f("email")},SubmitSelector:"#bm-auto-submit-1"}
 if b.kind=="signup" {
  switch b.page{
  case 0:return AuthPageState{Kind:"login",SignupPath:"/signup"},nil
  case 1:return AuthPageState{Kind:"signup",Fields:[]DiscoveredField{{Selector:"#bm-auto-field-1",Role:"email"},
   {Selector:"#bm-auto-field-2",Role:"password"},
   {Selector:"#bm-auto-field-3",Role:"password_confirm"}},SubmitSelector:"#bm-auto-submit-1",Ambiguous:b.ambiguous},nil
  case 2:return AuthPageState{Kind:"verification",Fields:[]DiscoveredField{f("otp")},SubmitSelector:"#bm-auto-submit-1"},nil
  }
 }
 if b.kind=="login"&&b.page==1{
  result.Fields=[]DiscoveredField{f("password")}
 }
 result.Ambiguous=b.ambiguous
 return result,nil
}
type adaptiveMockFactory struct {
 profiles map[string]*adaptiveMockBrowser
 closed int
 kind string
 ambiguous bool
 offscope bool
}
func (f *adaptiveMockFactory) New(_ context.Context,actor,origin string)(Browser,error){
 if f.profiles==nil{f.profiles=map[string]*adaptiveMockBrowser{}}
 b:=&adaptiveMockBrowser{kind:f.kind,closed:&f.closed,ambiguous:f.ambiguous,offscope:f.offscope}
 f.profiles[actor]=b
 return b,nil
}
func adaptiveScope()ApprovedScope{
 return ApprovedScope{EngagementID:"approved-adaptive",AllowedOrigins:[]string{"https://app.example"},
  ApprovedPostPaths:[]string{"/login","/signup","/verify"},
  MaxBrowserRequests:25,MaxTunnels:8,MinIntervalMS:100}
}
func adaptiveManifest()bunnyguard.Policy{
 return bunnyguard.Policy{EngagementID:"approved-adaptive",
  AllowedOrigins:[]string{"https://app.example"},AllowedMethods:[]string{"GET","HEAD","POST"},
  MaxNetworkCalls:120,MinIntervalMS:100}
}
func TestAdaptiveTwoPersonLoginDiscoversChangingForms(t *testing.T){
 cfg:=AdaptiveConfig{Origin:"https://app.example",StartPath:"/login",Mode:"login",
  Actors:[]string{"owner","peer"},SuccessText:"Signed in!"}
 factory:=&adaptiveMockFactory{kind:"login"}
 secrets:=&adaptiveFakeSecrets{}
 result,err:=RunAdaptive(context.Background(),cfg,adaptiveScope(),adaptiveManifest(),factory,secrets,nil,nil)
 if err!=nil{t.Fatal(err)}
 if result.Actors!=2||result.StepsCompleted!=4||factory.closed!=2{
  t.Fatalf("unexpected adaptive result %+v close=%d",result,factory.closed)
 }
 if len(secrets.used)!=4{t.Fatalf("expected identity-scoped credentials, got %v",secrets.used)}
 for _,b:=range factory.profiles{
  if b.page!=2||len(b.filled)!=2{t.Fatalf("form sequence incomplete: %+v",b)}
 }
}
func TestAdaptiveSignupAndEmailCode(t *testing.T){
 cfg:=AdaptiveConfig{Origin:"https://app.example",StartPath:"/login",Mode:"signup",
  Actors:[]string{"owner"},SuccessText:"Welcome account",
  UseEmailOTP:true,Mailboxes:map[string]MailboxSettings{"owner":{Host:"imap.example.com",Sender:"verify@example.com"}}}
 factory:=&adaptiveMockFactory{kind:"signup"}
 secrets:=&adaptiveFakeSecrets{}
 otp:=&adaptiveOTP{}
 result,err:=RunAdaptive(context.Background(),cfg,adaptiveScope(),adaptiveManifest(),factory,secrets,otp,nil)
 if err!=nil{t.Fatal(err)}
 if result.StepsCompleted!=2||otp.armed["owner"]!=1||otp.w["owner"]!=1||factory.closed!=1{
  t.Fatalf("signup transition failed %+v, otp=%+v",result,otp)
 }
 for _,event:=range result.Events{
  if strings.Contains(event.EvidenceSHA256,"673921"){t.Fatal("OTP leaked")}
 }
}
func TestAdaptiveRejectsAmbiguityAndRedirect(t *testing.T){
 cfg:=AdaptiveConfig{Origin:"https://app.example",StartPath:"/login",Mode:"login",Actors:[]string{"owner"},SuccessText:"Logged in"}
 for _,tc:=range []struct{ambiguous,offscope bool}{{ambiguous:true},{offscope:true}}{
  factory:=&adaptiveMockFactory{kind:"login",ambiguous:tc.ambiguous,offscope:tc.offscope}
  if _,err:=RunAdaptive(context.Background(),cfg,adaptiveScope(),adaptiveManifest(),factory,&adaptiveFakeSecrets{},nil,nil);err==nil{
   t.Fatalf("accepted unsafe browser workflow: %+v",tc)
  }
  if factory.closed!=1{t.Fatal("browser profile not cleaned on error")}
 }
}
func TestAdaptiveConfigurationRequiresExplicitBoundaries(t *testing.T){
 cfg:=AdaptiveConfig{Origin:"https://app.example",StartPath:"/login",Mode:"login",Actors:[]string{"owner","peer"},SuccessText:"Signed in!"}
 if err:=ValidateAdaptive(cfg,adaptiveScope(),adaptiveManifest());err!=nil{t.Fatal(err)}
 bad:=cfg;bad.Origin="https://external.example"
 if ValidateAdaptive(bad,adaptiveScope(),adaptiveManifest())==nil{t.Fatal("accepted offscope origin")}
 bad=cfg;bad.Actors=[]string{"owner","owner"}
 if ValidateAdaptive(bad,adaptiveScope(),adaptiveManifest())==nil{t.Fatal("duplicate persona")}
 bad=cfg;bad.StartPath="/../login"
 if ValidateAdaptive(bad,adaptiveScope(),adaptiveManifest())==nil{t.Fatal("path traversal accepted")}
 bad=cfg;bad.UseEmailOTP=true
 if ValidateAdaptive(bad,adaptiveScope(),adaptiveManifest())==nil{t.Fatal("OTP without mailbox")}
 bad=cfg;bad.Mailboxes=map[string]MailboxSettings{"owner":{Host:"imap.example.com",Sender:"verify@example.com"}}
 if ValidateAdaptive(bad,adaptiveScope(),adaptiveManifest())==nil{t.Fatal("unrequested mailbox")}
 scope:=adaptiveScope();scope.MaxBrowserRequests=61
 if ValidateAdaptive(cfg,scope,adaptiveManifest())==nil{t.Fatal("aggregate request quota ignored")}
}
var _=time.Second
