package bunnybrowserflow

import (
 "context"
 "errors"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
)
type extendedSecrets struct{}
func (extendedSecrets) Resolve(_ context.Context,actor,key string)(string,error){
 switch key{case "email":return actor+"@research.example",nil;case "password":return "test-account-password",nil;case "username":return actor,nil}
 return "",errors.New("missing test-account secret")
}
type extendedFactor struct{armed int; waits int; link string}
func (f *extendedFactor) Arm(_ context.Context,actor string)error{f.armed++;return nil}
func (f *extendedFactor) Wait(_ context.Context,actor string)(string,error){f.waits++;return "123456",nil}
func (f *extendedFactor) WaitLink(_ context.Context,actor string,allowed map[string]bool,prefixes []string)(string,error){
 f.waits++
 return f.link,nil
}
type extendedBrowser struct{
 kind string
 page int
 url string
 closed *int
 captures []string
}
func (b *extendedBrowser) Navigate(_ context.Context,u string)error{
 b.url=u
 if strings.Contains(u,"/auth/magic/verify"){b.page=5}
 return nil
}
func (b *extendedBrowser) Fill(_ context.Context,selector,value string)error{
 if !safeDiscoverySelector.MatchString(selector){return errors.New("unsafe form ref")}
 b.captures=append(b.captures,value)
 return nil
}
func (b *extendedBrowser) Click(_ context.Context,selector string)error{
 if !safeDiscoverySelector.MatchString(selector){return errors.New("unsafe click ref")}
 if b.kind=="idp"{
  if b.page==0 {b.url="https://idp.example/login";b.page=1}else if b.page==1{
   b.url="https://app.example/callback?code=private";b.page=5
  }
 }else if b.kind=="magic"{b.page=1
 }else{b.page=5}
 return nil
}
func (b *extendedBrowser) Contains(_ context.Context,expected string)(bool,error){return b.page==5,nil}
func (b *extendedBrowser) CurrentURL(_ context.Context)(string,error){return b.url,nil}
func (b *extendedBrowser) Close(){*b.closed++}
func (b *extendedBrowser) DiscoverAuth(_ context.Context)(AuthPageState,error){
 if b.kind=="idp"&&b.page==0{
  return AuthPageState{Kind:"unknown",ProviderSelector:"#bm-auto-provider-1"},nil
 }
 if b.kind=="idp"&&b.page==1{
  return AuthPageState{Kind:"login",Fields:[]DiscoveredField{
   {Selector:"#bm-auto-field-1",Role:"email"},
   {Selector:"#bm-auto-field-2",Role:"password"},
  },SubmitSelector:"#bm-auto-submit-1"},nil
 }
 if b.kind=="passkey"{
  return AuthPageState{Kind:"login",PasskeySelector:"#bm-auto-passkey-1"},nil
 }
 if b.kind=="captcha"{
  return AuthPageState{Kind:"challenge",Challenge:"anti_bot",CaptchaTestKey:true,CaptchaReady:true,
   Fields:[]DiscoveredField{{Selector:"#bm-auto-field-1",Role:"email"}},SubmitSelector:"#bm-auto-submit-1"},nil
 }
 if b.kind=="totp" {
  return AuthPageState{Kind:"verification",Fields:[]DiscoveredField{
   {Selector:"#bm-auto-field-1",Role:"otp"}},SubmitSelector:"#bm-auto-submit-1"},nil
 }
 return AuthPageState{Kind:"login",Fields:[]DiscoveredField{
  {Selector:"#bm-auto-field-1",Role:"email"}},SubmitSelector:"#bm-auto-submit-1"},nil
}
func (b *extendedBrowser) DiscoverAuthScoped(ctx context.Context,_ []string)(AuthPageState,error){
 return b.DiscoverAuth(ctx)
}
type extendedFactory struct{kind string;browser *extendedBrowser;closed int}
func (f *extendedFactory) New(_ context.Context,actor,origin string)(Browser,error){
 b:=&extendedBrowser{kind:f.kind,closed:&f.closed}
 f.browser=b;return b,nil
}
func extendedManifest()bunnyguard.Policy{
 return bunnyguard.Policy{EngagementID:"ext",AllowedOrigins:[]string{"https://app.example","https://idp.example"},
  AllowedMethods:[]string{"GET","HEAD","POST"},MaxNetworkCalls:200,MinIntervalMS:100}
}
func extendedScope()ApprovedScope{
 return ApprovedScope{EngagementID:"ext",AllowedOrigins:[]string{"https://app.example","https://idp.example"},
  ApprovedPostPaths:[]string{"/login","/callback"},MaxBrowserRequests:30,MaxTunnels:6,MinIntervalMS:150}
}
func baseExtendedConfig()AdaptiveConfig{
 return AdaptiveConfig{Origin:"https://app.example",StartPath:"/login",Mode:"login",
  Actors:[]string{"owner"},SuccessText:"Signed in test session"}
}
func TestAdaptiveApprovedSSORedirect(t *testing.T){
 cfg:=baseExtendedConfig();cfg.IdPOrigins=[]string{"https://idp.example"}
 factory:=&extendedFactory{kind:"idp"}
 r,err:=RunAdaptive(context.Background(),cfg,extendedScope(),extendedManifest(),factory,extendedSecrets{},nil,nil)
 if err!=nil{t.Fatal(err)}
 if r.Actors!=1||r.Outcome!="completed_adaptive_auth"||factory.closed!=1{
  t.Fatalf("SSO not verified: %+v",r)
 }
 if !strings.Contains(factory.browser.url,"/callback"){t.Fatal("SSO did not return to app callback")}
 found:=false
 for _,e:=range r.Events{if e.Action=="approved_sso_redirect"{found=true}}
 if !found{t.Fatal("IdP transition not recorded")}
}
func TestAdaptiveOwnedTOTPRequiresNoOperator(t *testing.T){
 cfg:=baseExtendedConfig();cfg.UseTOTP=true
 factory:=&extendedFactory{kind:"totp"}
 factors:=&extendedFactor{}
 r,err:=RunAdaptive(context.Background(),cfg,extendedScope(),extendedManifest(),factory,extendedSecrets{},factors,nil)
 if err!=nil||r.Actors!=1||factors.armed!=1||factors.waits!=1{t.Fatalf("TOTP flow failed %+v %v",r,err)}
}
func TestAdaptiveMagicLinkOnlyFromApprovedMailboxDestination(t *testing.T){
 cfg:=baseExtendedConfig()
 cfg.UseMagicLink=true
 cfg.Mailboxes=map[string]MailboxSettings{"owner":{Host:"imap.research.example",Sender:"login@app.example"}}
 cfg.MagicLinkPrefixes=[]string{"/auth/magic"}
 factors:=&extendedFactor{link:"https://app.example/auth/magic/verify?token=private-operator-mail-link"}
 factory:=&extendedFactory{kind:"magic"}
 r,err:=RunAdaptive(context.Background(),cfg,extendedScope(),extendedManifest(),factory,extendedSecrets{},factors,nil)
 if err!=nil||r.Actors!=1||factors.waits!=1{t.Fatalf("approved magic-link login failed: %+v %v",r,err)}
 factors=&extendedFactor{link:"https://evil.example/auth/magic/verify?token=exfil"}
 if _,err:=RunAdaptive(context.Background(),cfg,extendedScope(),extendedManifest(),&extendedFactory{kind:"magic"},extendedSecrets{},factors,nil);err==nil{
  t.Fatal("offscope magic link was accepted")
 }
}
func TestAutomaticOfficialCaptchaTestButNoLiveBypass(t *testing.T){
 cfg:=baseExtendedConfig();cfg.CaptchaTestMode=true
 r,err:=RunAdaptive(context.Background(),cfg,extendedScope(),extendedManifest(),&extendedFactory{kind:"captcha"},extendedSecrets{},nil,nil)
 if err!=nil||r.Actors!=1{t.Fatalf("official test-mode CAPTCHA should not require operator: %+v %v",r,err)}
 cfg.CaptchaTestMode=false
 if _,err:=RunAdaptive(context.Background(),cfg,extendedScope(),extendedManifest(),&extendedFactory{kind:"captcha"},extendedSecrets{},nil,nil);err==nil{
  t.Fatal("production CAPTCHA was silently bypassed")
 }
}
func TestUnapprovedIdPFailsPreflight(t *testing.T){
 cfg:=baseExtendedConfig();cfg.IdPOrigins=[]string{"https://evil.example"}
 if err:=ValidateAdaptive(cfg,extendedScope(),extendedManifest());err==nil{
  t.Fatal("SSO origin not in engagement accepted")
 }
}

func TestPlatformPasskeyDispatchAndNaturalCaptcha(t *testing.T){
 cfg:=baseExtendedConfig()
 cfg.PasskeyMode="platform"
 factory:=&extendedFactory{kind:"passkey"}
 out,err:=RunAdaptive(context.Background(),cfg,extendedScope(),extendedManifest(),factory,extendedSecrets{},nil,nil)
 if err!=nil||out.Actors!=1||out.StepsCompleted<1{
  t.Fatalf("browser-native passkey flow did not run: %+v %v",out,err)
 }
 cfg=baseExtendedConfig();cfg.AllowNaturalCaptcha=true
 out,err=RunAdaptive(context.Background(),cfg,extendedScope(),extendedManifest(),
  &extendedFactory{kind:"captcha"},extendedSecrets{},nil,nil)
 if err!=nil||out.Actors!=1{t.Fatalf("provider-generated CAPTCHA response not accepted: %+v %v",out,err)}
}
func TestVirtualPasskeyNeedsOperatorScopedTestMode(t *testing.T){
 cfg:=baseExtendedConfig()
 cfg.PasskeyMode="virtual_test"
 scope:=extendedScope()
 if err:=ValidateAdaptive(cfg,scope,extendedManifest());err==nil{
  t.Fatal("virtual authenticator allowed without explicit scope approval")
 }
 scope.AllowVirtualPasskey=true
 if err:=ValidateAdaptive(cfg,scope,extendedManifest());err!=nil{
  t.Fatalf("approved virtual authenticator rejected: %v",err)
 }
 cfg.PasskeyMode="unexpected"
 if err:=ValidateAdaptive(cfg,scope,extendedManifest());err==nil{
  t.Fatal("unrecognized WebAuthn option accepted")
 }
}
