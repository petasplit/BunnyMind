package bunnybrowserflow

import (
 "context"
 "errors"

 "github.com/enowdev/antares/internal/bunnyguard"
)

const MaxAdaptiveTransitions=12
type AdaptiveConfig struct {
 Actor string `json:"actor"`
 Mode string `json:"mode"`
 EntryPath string `json:"entry_path"`
}
type AdaptiveResult struct {
 Outcome string `json:"outcome"`
 Actor string `json:"actor"`
 Transitions int `json:"transitions"`
 DiscoveredFields int `json:"discovered_fields"`
 UsedMailboxOTP bool `json:"used_mailbox_otp"`
 OperatorHandoffs int `json:"operator_handoffs"`
 Events []Event `json:"events"`
 Traffic []TrafficReceipt `json:"traffic,omitempty"`
 Disclaimer string `json:"disclaimer"`
}
type OTPSince interface {
 MarkCodeRequested(actor string)
}
func validateAdaptive(c AdaptiveConfig)error{
 if !validActor.MatchString(c.Actor) || (c.Mode!="login"&&c.Mode!="signup") ||
  !safePath(c.EntryPath){
  return errors.New("adaptive authentication requires an approved actor, login/signup mode and safe entry path")
 }
 return nil
}
func snapshotField(s AuthSnapshot,kind string)(string,bool){
 for _,f:=range s.Fields{if f.Kind==kind{return f.Selector,true}}
 return "",false
}
func snapshotAction(s AuthSnapshot,kind string)(string,bool){
 for _,a:=range s.Actions{if a.Kind==kind{return a.Selector,true}}
 return "",false
}
func snapshotLink(s AuthSnapshot,kind string)(string,bool){
 for _,a:=range s.Links{if a.Kind==kind&&safePath(a.Path){return a.Path,true}}
 return "",false
}
func appendAdaptive(result *AdaptiveResult,actor,kind string){
 seq:=len(result.Events)+1
 result.Events=append(result.Events,Event{Seq:seq,Actor:actor,Action:kind,
  Outcome:"succeeded",EvidenceSHA256:proof(actor,kind,"succeeded",seq)})
}
func captureAdaptive(ctx context.Context,result *AdaptiveResult,b Browser,approved map[string]bool){
 if observer,ok:=b.(TrafficObserver);ok && len(result.Traffic)<MaxTrafficReceipts{
  rr:=observer.CaptureTraffic(ctx,result.Actor,result.Transitions,approved)
  rem:=MaxTrafficReceipts-len(result.Traffic)
  if len(rr)>rem{rr=rr[:rem]}
  result.Traffic=append(result.Traffic,rr...)
 }
}
func secureSnapshot(ctx context.Context,b Browser,approved map[string]bool)(AuthSnapshot,error){
 raw,err:=b.CurrentURL(ctx)
 if err!=nil||!approvedBrowserURL(raw,approved){return AuthSnapshot{},errors.New("browser left approved origin")}
 inspect,ok:=b.(AuthInspector)
 if !ok{return AuthSnapshot{},errors.New("trusted browser cannot inspect forms")}
 snap,err:=inspect.InspectAuth(ctx)
 if err!=nil{return AuthSnapshot{},err}
 if err:=validateAuthSnapshot(snap);err!=nil{return AuthSnapshot{},err}
 return snap,nil
}
// RunAdaptiveApproved uses only a small set of preapproved benign auth actions.
// It never guesses or mutates arbitrary parameters, tries password lists,
// bypasses anti-bot prompts, or submits unbounded forms. The browser network
// gate independently restricts every HTTP request and POST destination.
func RunAdaptiveApproved(ctx context.Context,c AdaptiveConfig,scope ApprovedScope,
 factory Factory,secrets Secrets,operator Handoff,manifest bunnyguard.Policy)(AdaptiveResult,error){
 if err:=validateAdaptive(c);err!=nil{return AdaptiveResult{},err}
 allowed,err:=ValidateApprovedScope(scope,manifest)
 if err!=nil{return AdaptiveResult{},err}
 if scope.MaxBrowserRequests>manifest.MaxNetworkCalls{
  return AdaptiveResult{},errors.New("adaptive request budget exceeds engagement")
 }
 if len(scope.ApprovedPostPaths)==0{
  return AdaptiveResult{},errors.New("adaptive form submission requires explicitly approved POST paths")
 }
 if factory==nil||secrets==nil{return AdaptiveResult{},errors.New("trusted browser and credential provider required")}
 start,err:=strictOrigin(scope.AllowedOrigins[0])
 if err!=nil||!allowed[start]{return AdaptiveResult{},errors.New("approved entry origin missing")}
 b,err:=factory.New(ctx,c.Actor,start)
 if err!=nil||b==nil{return AdaptiveResult{},errors.New("trusted browser could not start")}
 defer b.Close()
 result:=AdaptiveResult{Actor:c.Actor,Outcome:"needs_operator_review",Events:[]Event{},
  Disclaimer:"Redacted metadata reflects only scope-approved authentication actions; it does not independently prove sign-in, account ownership or a vulnerability."}
 if err:=b.Navigate(ctx,start+c.EntryPath);err!=nil{return AdaptiveResult{},errors.New("approved entry page navigation failed")}
 visited:=map[string]bool{c.EntryPath:true}
 acted:=map[string]bool{}
 submitted:=false
 emailStageCompleted:=false
 requestedOTP:=false
 for i:=0;i<MaxAdaptiveTransitions;i++{
  if ctx.Err()!=nil{return AdaptiveResult{},ctx.Err()}
  result.Transitions++
  snap,err:=secureSnapshot(ctx,b,allowed)
  if err!=nil{return AdaptiveResult{},err}
  result.DiscoveredFields+=len(snap.Fields)
  if snap.SignedIn {
   result.Outcome="sign_in_indicator_observed"
   appendAdaptive(&result,c.Actor,"signed_in_indicator")
   captureAdaptive(ctx,&result,b,allowed)
   return result,nil
  }
  if snap.Challenge!=""{
   if acted["handoff"]||operator==nil{
    result.Outcome="operator_verification_required"
    return result,nil
   }
   if err:=operator.Authorize(ctx,c.Actor,snap.Challenge);err!=nil{
    return AdaptiveResult{},errors.New("operator verification not completed")
   }
   acted["handoff"]=true
   result.OperatorHandoffs++
   appendAdaptive(&result,c.Actor,"operator_handoff")
   captureAdaptive(ctx,&result,b,allowed)
   continue
  }
  if otpSelector,ok:=snapshotField(snap,"otp");ok {
   if requestedOTP{result.Outcome="verification_pending";return result,nil}
   if !submitted&&!emailStageCompleted{result.Outcome="verification_not_requested";return result,nil}
   code,err:=secrets.Resolve(ctx,c.Actor,"otp")
   if err!=nil||len(code)==0||len(code)>32{
    result.Outcome="trusted_mailbox_code_unavailable"
    return result,nil
   }
   if err:=b.Fill(ctx,otpSelector,code);err!=nil{return AdaptiveResult{},errors.New("approved code field entry failed")}
   code=""
   button,ok:=snapshotAction(snap,"verify")
   if !ok{result.Outcome="verification_submit_missing";return result,nil}
   if err:=b.Click(ctx,button);err!=nil{return AdaptiveResult{},errors.New("approved verification click failed")}
   requestedOTP=true
   result.UsedMailboxOTP=true
   appendAdaptive(&result,c.Actor,"otp_verified_submission")
   captureAdaptive(ctx,&result,b,allowed)
   continue
  }
  if !submitted{
   needed:="password"
   emailSelector,hasEmail:=snapshotField(snap,"email")
   passSelector,hasPassword:=snapshotField(snap,needed)
   if !hasEmail{
    emailSelector,hasEmail=snapshotField(snap,"username")
   }
   if hasEmail && !hasPassword && !emailStageCompleted{
    action,ok:=snapshotAction(snap,c.Mode)
    if !ok{action,ok=snapshotAction(snap,"login")}
    if ok{
     key:="email"
     if _,isEmail:=snapshotField(snap,"email");!isEmail{key="username"}
     identity,err:=secrets.Resolve(ctx,c.Actor,key)
     if err!=nil||len(identity)==0||len(identity)>256{
      return AdaptiveResult{},errors.New("trusted first-stage identity unavailable")
     }
     if err:=b.Fill(ctx,emailSelector,identity);err!=nil{return AdaptiveResult{},errors.New("first-stage identity fill failed")}
     identity=""
     if marker,ok:=secrets.(OTPSince);ok{marker.MarkCodeRequested(c.Actor)}
     if err:=b.Click(ctx,action);err!=nil{return AdaptiveResult{},errors.New("approved email-first submission failed")}
     emailStageCompleted=true
     appendAdaptive(&result,c.Actor,"email_first_step_submitted")
     captureAdaptive(ctx,&result,b,allowed)
     continue
    }
   }
   if (!hasEmail&&!emailStageCompleted)||!hasPassword{
    if link,ok:=snapshotLink(snap,c.Mode);ok&&!visited[link]&&len(visited)<3{
     visited[link]=true
     if err:=b.Navigate(ctx,start+link);err!=nil{return AdaptiveResult{},errors.New("approved auth link navigation failed")}
     appendAdaptive(&result,c.Actor,"auth_link_navigation")
     captureAdaptive(ctx,&result,b,allowed)
     continue
    }
    result.Outcome="unknown_or_unsupported_auth_form"
    return result,nil
   }
   if hasEmail{
    identityKey:="email"
    if _,ok:=snapshotField(snap,"email");!ok{identityKey="username"}
    identity,err:=secrets.Resolve(ctx,c.Actor,identityKey)
    if err!=nil||len(identity)==0||len(identity)>256{return AdaptiveResult{},errors.New("trusted test-account identity missing")}
    if err:=b.Fill(ctx,emailSelector,identity);err!=nil{return AdaptiveResult{},errors.New("account field entry failed")}
    identity=""
   }
   password,err:=secrets.Resolve(ctx,c.Actor,"password")
   if err!=nil||len(password)==0||len(password)>256{
    return AdaptiveResult{},errors.New("trusted test-account password missing")
   }
   if err:=b.Fill(ctx,passSelector,password);err!=nil{return AdaptiveResult{},errors.New("password field entry failed")}
   if c.Mode=="signup"{
    if confirmation,ok:=snapshotField(snap,"confirm_password");ok{
     if err:=b.Fill(ctx,confirmation,password);err!=nil{return AdaptiveResult{},errors.New("password confirmation failed")}
    }
   }
   password=""
   button,ok:=snapshotAction(snap,c.Mode)
   if !ok{result.Outcome="ambiguous_auth_submission";return result,nil}
   if marker,ok:=secrets.(OTPSince);ok{marker.MarkCodeRequested(c.Actor)}
   if err:=b.Click(ctx,button);err!=nil{return AdaptiveResult{},errors.New("auth submission failed")}
   submitted=true
   appendAdaptive(&result,c.Actor,c.Mode+"_form_submitted")
   captureAdaptive(ctx,&result,b,allowed)
   continue
  }
  // A login after a verified registration is an expected state transition,
  // but never retry the same action on an unchanged page.
  if requestedOTP && !acted["post_verification_login"]{
   if link,ok:=snapshotLink(snap,"login");ok&&!visited[link]&&len(visited)<3{
    acted["post_verification_login"]=true
    visited[link]=true
    if err:=b.Navigate(ctx,start+link);err!=nil{return AdaptiveResult{},errors.New("post-verification login navigation failed")}
    appendAdaptive(&result,c.Actor,"post_verification_login_navigation")
    captureAdaptive(ctx,&result,b,allowed)
    return result,nil // Do not guess a second credential submission.
   }
  }
  result.Outcome="submitted_needs_review"
  return result,nil
 }
 result.Outcome="transition_budget_exhausted"
 return result,nil
}
