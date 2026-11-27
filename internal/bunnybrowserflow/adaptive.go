package bunnybrowserflow

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnyguard"
)
const maxAdaptiveRounds=8
type AdaptiveConfig struct {
 Origin string `json:"origin"`
 StartPath string `json:"start_path"`
 Mode string `json:"mode"`
 Actors []string `json:"actors"`
 SuccessText string `json:"success_text"`
 UseEmailOTP bool `json:"use_email_otp"`
 UseTOTP bool `json:"use_totp,omitempty"`
 UseMagicLink bool `json:"use_magic_link,omitempty"`
 MagicLinkPrefixes []string `json:"magic_link_prefixes,omitempty"`
 IdPOrigins []string `json:"idp_origins,omitempty"`
 CaptchaTestMode bool `json:"captcha_test_mode,omitempty"`
 Mailboxes map[string]MailboxSettings `json:"mailboxes,omitempty"`
}
type OTPProvider interface {
 Arm(context.Context,string)error
 Wait(context.Context,string)(string,error)
}
func ValidateAdaptive(cfg AdaptiveConfig,scope ApprovedScope,manifest bunnyguard.Policy)error{
 allowed,err:=ValidateApprovedScope(scope,manifest)
 if err!=nil{return err}
 origin,err:=strictOrigin(cfg.Origin)
 if err!=nil||!allowed[origin]{return errors.New("adaptive login origin outside approved scope")}
 if !safePath(cfg.StartPath){return errors.New("invalid adaptive starting path")}
 if cfg.Mode!="signup"&&cfg.Mode!="login"{return errors.New("adaptive mode must be signup or login")}
 if len(cfg.Actors)==0||len(cfg.Actors)>MaxActors{return errors.New("1..4 explicit test identities required")}
 seen:=map[string]bool{}
 for _,actor:=range cfg.Actors{
  if !validActor.MatchString(actor)||seen[actor]{return errors.New("invalid/duplicate test persona")}
  seen[actor]=true
 }
 if len(cfg.SuccessText)<4||len(cfg.SuccessText)>80||
  strings.ContainsAny(cfg.SuccessText,"\r\n"){return errors.New("unique expected signed-in text is required")}
 if scope.MaxBrowserRequests*len(cfg.Actors)>manifest.MaxNetworkCalls{
  return errors.New("aggregate adaptive browser request budget exceeds permission")
 }
 if len(scope.ApprovedPostPaths)==0{return errors.New("adaptive auth requires explicitly approved POST paths")}
 factors:=0
 if cfg.UseEmailOTP{factors++}
 if cfg.UseTOTP{factors++}
 if cfg.UseMagicLink{factors++}
 if factors>1{return errors.New("select one trusted factor type per adaptive workflow")}
 if cfg.UseEmailOTP||cfg.UseMagicLink{
  if len(cfg.Mailboxes)!=len(cfg.Actors){return errors.New("each verification persona requires its own configured mailbox")}
  for _,actor:=range cfg.Actors{if _,ok:=cfg.Mailboxes[actor];!ok{return errors.New("missing approved actor mailbox")}}
  if _,err:=NewIMAPOTP(cfg.Mailboxes,KeyringSecrets{});err!=nil{return err}
 }else if len(cfg.Mailboxes)!=0{return errors.New("mailboxes supplied without email verification")}
 if cfg.UseMagicLink{
  if len(cfg.MagicLinkPrefixes)==0||len(cfg.MagicLinkPrefixes)>12{return errors.New("magic link endpoint allowlist is required")}
  for _,prefix:=range cfg.MagicLinkPrefixes{
   if !safePath(prefix){return errors.New("invalid operator-approved magic link path prefix")}
  }
 }else if len(cfg.MagicLinkPrefixes)!=0{return errors.New("unexpected magic link path allowlist")}
 if len(cfg.IdPOrigins)>8{return errors.New("too many approved identity-provider origins")}
 seenIDP:=map[string]bool{}
 for _,raw:=range cfg.IdPOrigins{
  idp,err:=strictOrigin(raw)
  if err!=nil||!allowed[idp]||idp==origin||seenIDP[idp]{
   return errors.New("identity provider must be a distinct explicitly approved HTTPS origin")
  }
  seenIDP[idp]=true
 }
 return nil
}
func fieldForRole(fields []DiscoveredField,role string)string{
 for _,f:=range fields{if f.Role==role{return f.Selector}}
 return ""
}
func uniqueState(s AuthPageState)string {
 var parts []string
 for _,f:=range s.Fields{parts=append(parts,f.Role)}
 return s.Kind+"|"+strings.Join(parts,",")+"|"+s.SignupPath+"|"+s.LoginPath
}
func adaptiveDigest(actor,action string,step int)string{
 h:=sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d",actor,action,step)))
 return hex.EncodeToString(h[:])
}
// RunAdaptive discovers fields on the *actual* approved page. It never takes
// a model-written selector or action list; account identities, expected
// signed-in indicator, capabilities and limits are operator configured.
func RunAdaptive(ctx context.Context,cfg AdaptiveConfig,scope ApprovedScope,manifest bunnyguard.Policy,
 factory Factory,secrets Secrets,otp OTPProvider,operator Handoff)(Result,error){
 if err:=ValidateAdaptive(cfg,scope,manifest);err!=nil{return Result{},err}
 if factory==nil||secrets==nil{return Result{},errors.New("trusted browser and credential providers required")}
 if cfg.UseEmailOTP&&otp==nil{return Result{},errors.New("email OTP requires a trusted mailbox adapter")}
 origin,_:=strictOrigin(cfg.Origin)
 allow:=map[string]bool{}
 for _,v:=range scope.AllowedOrigins{o,_:=strictOrigin(v);allow[o]=true}
 result:=Result{Outcome:"completed_adaptive_auth",Events:[]Event{},
  Disclaimer:"Operator-scoped browser observations and login indicators are not proof of a vulnerability. Raw credentials and mailbox content are never returned."}
 sessions:=map[string]Browser{}
 defer func(){for _,session:=range sessions{session.Close()}}()
 for _,actor:=range cfg.Actors {
  b,err:=factory.New(ctx,actor,origin)
  if err!=nil||b==nil{return Result{},errors.New("trusted adaptive browser start failed")}
  sessions[actor]=b
  if err:=b.Navigate(ctx,origin+cfg.StartPath);err!=nil{return Result{},errors.New("approved authentication page unavailable")}
  current,err:=b.CurrentURL(ctx)
  if err!=nil||!approvedBrowserURL(current,allow){return Result{},errors.New("initial browser navigation escaped scope")}
  // A pre-existing banner with the expected words is not login evidence.
  if wasLoggedIn,e:=b.Contains(ctx,cfg.SuccessText);e==nil&&wasLoggedIn{
   return Result{},errors.New("expected success text is present before authentication")
  }
  if cfg.UseEmailOTP{
   if err:=otp.Arm(ctx,actor);err!=nil{return Result{},errors.New("trusted mailbox baseline unavailable")}
  }
  discovered,ok:=b.(DiscoveryBrowser)
  if !ok{return Result{},errors.New("browser does not support form discovery")}
  previous:=""
  complete:=false
  for round:=1;round<=maxAdaptiveRounds;round++{
   if err:=ctx.Err();err!=nil{return Result{},err}
   state,err:=discovered.DiscoverAuth(ctx)
   if err!=nil{return Result{},errors.New("auth form discovery failed")}
   if err:=validateDiscovery(state);err!=nil{return Result{},err}
   if state.Ambiguous{return Result{},fmt.Errorf("ambiguous authentication actions for %s; operator review required",actor)}
   if state.Challenge!=""{
    if operator==nil{return Result{},fmt.Errorf("%s requires operator %s handoff",actor,state.Challenge)}
    handoffCtx,cancel:=context.WithTimeout(ctx,2*time.Minute)
    e:=operator.Authorize(handoffCtx,actor,state.Challenge)
    cancel()
    if e!=nil{return Result{},errors.New("operator verification was not completed")}
    previous=""
    continue
   }
   if cfg.Mode=="signup"&&(state.Kind=="login"||state.Kind=="unknown")&&state.SignupPath!="" {
    if err:=b.Navigate(ctx,origin+state.SignupPath);err!=nil{return Result{},errors.New("approved registration link failed")}
    current,e:=b.CurrentURL(ctx)
    if e!=nil||!approvedBrowserURL(current,allow){return Result{},errors.New("registration link left approved scope")}
    previous=""
    continue
   }
   if cfg.Mode=="login"&&(state.Kind=="unknown"||state.Kind=="signup")&&state.LoginPath!="" {
    if err:=b.Navigate(ctx,origin+state.LoginPath);err!=nil{return Result{},errors.New("approved sign-in link failed")}
    current,e:=b.CurrentURL(ctx)
    if e!=nil||!approvedBrowserURL(current,allow){return Result{},errors.New("sign-in link left approved scope")}
    previous=""
    continue
   }
   if cfg.Mode=="signup"&&state.Kind=="login"&&!strings.Contains(cfg.StartPath,"signup")&&
    !strings.Contains(cfg.StartPath,"register")&&state.SignupPath=="" {
    return Result{},errors.New("registration action not identified; operator review required")
   }
   signature:=uniqueState(state)
   if signature==previous{return Result{},fmt.Errorf("authentication page did not advance for %s",actor)}
   previous=signature
   fieldsFilled:=0
   otpValue:=""
   for _,f:=range state.Fields{
    key:=""
    switch f.Role{
    case "email":key="email"
    case "username":key="username"
    case "password","password_confirm":key="password"
    case "otp":
     if !cfg.UseEmailOTP{return Result{},errors.New("OTP requested but trusted mailbox integration is disabled")}
     if otpValue==""{
      code,e:=otp.Wait(ctx,actor)
      if e!=nil{return Result{},errors.New("verification email unavailable or untrusted")}
      if len(code)<6||len(code)>8{return Result{},errors.New("invalid verification code length")}
      otpValue=code
     }
    }
    value:=otpValue
    if key!="" {
     var e error
     value,e=secrets.Resolve(ctx,actor,key)
     if e!=nil{return Result{},errors.New("configured test-account credential unavailable")}
    }
    if value==""{continue}
    if err:=b.Fill(ctx,f.Selector,value);err!=nil{return Result{},errors.New("discovered authentication field not fillable")}
    value="" // keep raw credentials out of events and reports
    fieldsFilled++
   }
   otpValue=""
   if fieldsFilled==0||state.SubmitSelector==""{
    return Result{},fmt.Errorf("no unambiguous fillable auth form for %s; operator review required",actor)
   }
   if err:=b.Click(ctx,state.SubmitSelector);err!=nil{return Result{},errors.New("approved form submission failed")}
   current,err:=b.CurrentURL(ctx)
   if err!=nil||!approvedBrowserURL(current,allow){return Result{},errors.New("form navigation left approved scope")}
   seq:=len(result.Events)+1
   result.Events=append(result.Events,Event{Seq:seq,Actor:actor,Action:"discovered_form_submit",
    Outcome:"observed",EvidenceSHA256:adaptiveDigest(actor,signature,seq)})
   if recorder,ok:=b.(TrafficObserver);ok&&len(result.Traffic)<MaxTrafficReceipts{
    receipts:=recorder.CaptureTraffic(ctx,actor,seq,allow)
    remaining:=MaxTrafficReceipts-len(result.Traffic)
    if len(receipts)>remaining{receipts=receipts[:remaining]}
    result.Traffic=append(result.Traffic,receipts...)
   }
   result.StepsCompleted++
   if yes,e:=b.Contains(ctx,cfg.SuccessText);e==nil&&yes{complete=true;break}
  }
  if !complete{return Result{},fmt.Errorf("authentication for %s remained unverified within experiment budget",actor)}
 }
 result.Actors=len(sessions)
 result.NextChecks=AnalyzeAuthNextChecks(result)
 return result,nil
}
