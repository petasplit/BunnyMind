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
 PasskeyMode string `json:"passkey_mode,omitempty"`
 AllowNaturalCaptcha bool `json:"allow_natural_captcha,omitempty"`

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
 switch cfg.PasskeyMode{
 case "","off","platform":
 case "virtual_test":
  if !scope.AllowVirtualPasskey{return errors.New("virtual passkey requires explicit test-scope approval")}
 default:return errors.New("unsupported WebAuthn mode")
 }
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
 return s.Kind+"|"+strings.Join(parts,",")+"|"+s.SignupPath+"|"+s.LoginPath+"|"+s.ProviderSelector
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
 if (cfg.UseEmailOTP||cfg.UseTOTP||cfg.UseMagicLink)&&otp==nil{return Result{},errors.New("trusted verification provider required")}
 origin,_:=strictOrigin(cfg.Origin)
 allow:=map[string]bool{}
 for _,v:=range scope.AllowedOrigins{o,_:=strictOrigin(v);allow[o]=true}
 idpOrigins:=make([]string,0,len(cfg.IdPOrigins))
 for _,v:=range cfg.IdPOrigins{o,_:=strictOrigin(v);idpOrigins=append(idpOrigins,o)}
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
  if cfg.UseEmailOTP||cfg.UseTOTP||cfg.UseMagicLink{
   if err:=otp.Arm(ctx,actor);err!=nil{return Result{},errors.New("trusted verification factor unavailable")}
  }
  discovered,ok:=b.(DiscoveryBrowser)
  if !ok{return Result{},errors.New("browser does not support form discovery")}
  previous:=""
  complete:=false
  magicConsumed:=false
  captchaWaits:=0
  captchaClicked:=false
  for round:=1;round<=maxAdaptiveRounds;round++{
   if err:=ctx.Err();err!=nil{return Result{},err}
   var state AuthPageState
   if scoped,yes:=discovered.(ScopedDiscoveryBrowser);yes{
    state,err=scoped.DiscoverAuthScoped(ctx,idpOrigins)
   }else{state,err=discovered.DiscoverAuth(ctx)}
   if err!=nil{return Result{},errors.New("auth form discovery failed")}
   if err:=validateDiscovery(state);err!=nil{return Result{},err}
   if capture,ok:=b.(EvidenceScreenshotter);ok&&len(result.Screenshots)<64{
    shot,e:=capture.RecordScreenshot(ctx,actor,stateScreenshotStage(state))
    if e!=nil{return Result{},errors.New("encrypted authentication screenshot could not be saved")}
    if shot.File!=""{result.Screenshots=append(result.Screenshots,shot)}
   }
   if state.Ambiguous{return Result{},fmt.Errorf("ambiguous authentication actions for %s; operator review required",actor)}
   if cfg.PasskeyMode!=""&&cfg.PasskeyMode!="off"&&state.PasskeySelector!=""{
    before,_:=b.CurrentURL(ctx)
    if err:=b.Click(ctx,state.PasskeySelector);err!=nil{
     return Result{},errors.New("approved WebAuthn button could not be activated")
    }
    signed,e:=awaitAuthProgress(ctx,b,discovered,uniqueState(state),before,cfg.SuccessText,allow,idpOrigins)
    if e!=nil{return Result{},e}
    step:=len(result.Events)+1
    result.Events=append(result.Events,Event{Seq:step,Actor:actor,
     Action:"webauthn_browser_auth",Outcome:"observed",
     EvidenceSHA256:adaptiveDigest(actor,"webauthn",step)})
    result.StepsCompleted++
    if signed{complete=true;break}
    previous=""
    continue
   }
   if state.Challenge!=""{
    if state.Challenge=="anti_bot"&&((cfg.CaptchaTestMode&&state.CaptchaTestKey)||cfg.AllowNaturalCaptcha){
     if !state.CaptchaReady{
      // Only official public test keys may receive an automated pointer
      // click. Production challenges are never solved or spoofed here.
      if cfg.CaptchaTestMode&&state.CaptchaTestKey&&!captchaClicked {
       if clicker,ok:=b.(OfficialTestChallengeInteraction);ok{
        clicked,e:=clicker.ClickOfficialTestChallenge(ctx)
        if e!=nil{return Result{},errors.New("test CAPTCHA interaction failed")}
        captchaClicked=clicked
       }
      }
      captchaWaits++
      if captchaWaits>3{return Result{},errors.New("approved CAPTCHA has not completed naturally; user or site-owner exemption required")}
      select{
      case <-ctx.Done():return Result{},ctx.Err()
      case <-time.After(500*time.Millisecond):
      }
      continue
     }
     // A response was generated by the page or provider. This does not
     // bypass challenge verification; the server must still accept it.
    }else{
     if operator==nil{return Result{},fmt.Errorf("%s requires operator %s handoff",actor,state.Challenge)}
     handoffCtx,cancel:=context.WithTimeout(ctx,2*time.Minute)
     e:=operator.Authorize(handoffCtx,actor,state.Challenge)
     cancel()
     if e!=nil{return Result{},errors.New("operator verification was not completed")}
     previous=""
     continue
    }
   }
   if state.ProviderSelector!=""&&len(state.Fields)==0{
    before,_:=b.CurrentURL(ctx)
    if err:=b.Click(ctx,state.ProviderSelector);err!=nil{return Result{},errors.New("approved SSO control could not be opened")}
    if switcher,ok:=b.(PopupBrowser);ok{
     if _,err:=switcher.SwitchToApprovedPopup(ctx);err!=nil{
      return Result{},errors.New("scoped SSO popup could not be attached")
     }
    }
    signed,e:=awaitAuthProgress(ctx,b,discovered,uniqueState(state),before,cfg.SuccessText,allow,idpOrigins)
    if e!=nil{return Result{},e}
    current,e:=b.CurrentURL(ctx)
    if e!=nil||!approvedBrowserURL(current,allow){return Result{},errors.New("SSO redirect left approved origins")}
    seq:=len(result.Events)+1
    result.Events=append(result.Events,Event{Seq:seq,Actor:actor,Action:"approved_sso_redirect",
     Outcome:"observed",EvidenceSHA256:adaptiveDigest(actor,"idp_redirect",seq)})
    if signed{complete=true;break}
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
     if !(cfg.UseEmailOTP||cfg.UseTOTP){return Result{},errors.New("OTP requested without an approved owned second factor")}
     if otpValue==""{
      code,e:=otp.Wait(ctx,actor)
      if e!=nil{return Result{},errors.New("trusted second-factor verification unavailable")}
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
   beforeURL,_:=b.CurrentURL(ctx)
   if err:=b.Click(ctx,state.SubmitSelector);err!=nil{return Result{},errors.New("approved form submission failed")}
   if capture,ok:=b.(EvidenceScreenshotter);ok&&len(result.Screenshots)<64{
    shot,e:=capture.RecordScreenshot(ctx,actor,"after_submit")
    if e!=nil{return Result{},errors.New("encrypted submission screenshot could not be saved")}
    if shot.File!=""{result.Screenshots=append(result.Screenshots,shot)}
   }
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
   if cfg.UseMagicLink&&!magicConsumed{
    provider,ok:=otp.(MagicLinkProvider)
    if !ok{return Result{},errors.New("trusted magic-link provider is not configured")}
    link,e:=provider.WaitLink(ctx,actor,allow,cfg.MagicLinkPrefixes)
    if e!=nil{return Result{},errors.New("approved mailbox magic link unavailable")}
    if !magicLinkAllowed(link,allow,cfg.MagicLinkPrefixes){
     return Result{},errors.New("mail link destination outside approved sign-in callbacks")
    }
    if e=b.Navigate(ctx,link);e!=nil{return Result{},errors.New("approved magic link browser navigation failed")}
    if after,e:=b.CurrentURL(ctx);e!=nil||!approvedBrowserURL(after,allow){
     return Result{},errors.New("magic link redirected outside approved scope")
    }
    magicConsumed=true
    linkSeq:=len(result.Events)+1
    result.Events=append(result.Events,Event{Seq:linkSeq,Actor:actor,
     Action:"trusted_magic_link_open",Outcome:"observed",
     EvidenceSHA256:adaptiveDigest(actor,"magic_link",linkSeq)})
    if yes,e:=b.Contains(ctx,cfg.SuccessText);e==nil&&yes{complete=true;break}
   }
   succeeded,e:=awaitAuthProgress(ctx,b,discovered,signature,beforeURL,cfg.SuccessText,allow,idpOrigins)
   if e!=nil{return Result{},e}
   if succeeded{complete=true;break}
  }
  if !complete{return Result{},fmt.Errorf("authentication for %s remained unverified within experiment budget",actor)}
 }
 result.Actors=len(sessions)
 result.NextChecks=AnalyzeAuthNextChecks(result)
 return result,nil
}
