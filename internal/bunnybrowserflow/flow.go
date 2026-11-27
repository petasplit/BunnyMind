// Package bunnybrowserflow runs constrained, operator-authored account
// workflows in isolated browser profiles. It never selects public targets,
// creates credentials, or bypasses a verification challenge on its own.
package bunnybrowserflow

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "net"
 "net/url"
 "regexp"
 "strings"
 "time"
)

const (
 MaxActors=4
 MaxSteps=32
 OpNavigate="navigate"
 OpFill="fill_secret"
 OpClick="click"
 OpAssert="assert_text"
 OpHandoff="operator_handoff"
)
var validActor=regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var validSelector=regexp.MustCompile(`^[a-zA-Z0-9_#.= -]{1,100}// Package bunnybrowserflow runs constrained, operator-authored account
// workflows in isolated browser profiles. It never selects public targets,
// creates credentials, or bypasses a verification challenge on its own.
package bunnybrowserflow

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "net"
 "net/url"
 "regexp"
 "strings"
 "time"
)

const (
 MaxActors=4
 MaxSteps=32
 OpNavigate="navigate"
 OpFill="fill_secret"
 OpClick="click"
 OpAssert="assert_text"
 OpHandoff="operator_handoff"
)
var validActor=regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
)
var validKey=regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var validPath=regexp.MustCompile(`^/[a-zA-Z0-9_./%-]{0,255}$`)

// Plan is supplied by trusted local application configuration, not generated
// dynamically by a model. It contains no credentials or OTP values.
type Plan struct {
 Origin string
 Steps []Step
}
type Step struct {
 Actor string
 Op string
 Path string
 Selector string
 SecretKey string
 ExpectedText string
 ChallengeKind string
}
type Browser interface {
 Navigate(context.Context,string)error
 Fill(context.Context,string,string)error
 Click(context.Context,string)error
 Contains(context.Context,string)(bool,error)
 CurrentURL(context.Context)(string,error)
 Close()
}
type Factory interface{New(context.Context,string,string)(Browser,error)}
type Secrets interface{Resolve(context.Context,string,string)(string,error)}
// Handoff is implemented by a trusted operator-controlled caller. No
// agent-facing endpoint or boolean bypass is offered by this package.
type Handoff interface{Authorize(context.Context,string,string)error}
type Event struct {
 Seq int `json:"seq"`
 Actor string `json:"actor"`
 Action string `json:"action"`
 Outcome string `json:"outcome"`
 EvidenceSHA256 string `json:"evidence_sha256"`
}
type Result struct{
 Outcome string `json:"outcome"`
 Actors int `json:"actors"`
 StepsCompleted int `json:"steps_completed"`
 Events []Event `json:"events"`
 Disclaimer string `json:"disclaimer"`
}

func Origin(raw string)(string,error){
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.Scheme!="http"||u.User!=nil||
  u.Opaque!=""||u.Hostname()==""||u.Port()==""||u.Path!=""||
  u.RawQuery!=""||u.Fragment!=""{
   return "",errors.New("only exact numeric-loopback HTTP origins with port are supported")
 }
 ip:=net.ParseIP(u.Hostname())
 if ip==nil||!ip.IsLoopback(){return "",errors.New("public and internal DNS targets are unavailable in the local browser lab")}
 return "http://"+u.Host,nil
}
func safePath(path string)bool{
 if !validPath.MatchString(path)||strings.HasPrefix(path,"//")||
  strings.Contains(path,"\\")||strings.Contains(path,"%2f")||strings.Contains(path,"%2F")||
  strings.Contains(path,"%5c")||strings.Contains(path,"%5C"){return false}
 for _,segment:=range strings.Split(path,"/"){
  if segment=="."||segment==".."{return false}
 }
 decoded,err:=url.PathUnescape(path)
 if err!=nil||strings.HasPrefix(decoded,"//")||strings.Contains(decoded,"\\"){return false}
 for _,segment:=range strings.Split(decoded,"/"){
  if segment=="."||segment==".."{return false}
 }
 return true
}
func Validate(p Plan)error {
 if _,err:=Origin(p.Origin);err!=nil{return err}
 if len(p.Steps)==0||len(p.Steps)>MaxSteps{return errors.New("plan needs 1..32 steps")}
 actors:=map[string]bool{}
 initialized:=map[string]bool{}
 for i,s:=range p.Steps {
  if !validActor.MatchString(s.Actor){return fmt.Errorf("step %d has invalid test persona",i+1)}
  actors[s.Actor]=true
  if len(actors)>MaxActors{return errors.New("too many browser profiles")}
  switch s.Op {
  case OpNavigate:
   if !safePath(s.Path)||s.Selector!=""||s.SecretKey!=""||s.ExpectedText!=""||s.ChallengeKind!=""{
    return fmt.Errorf("step %d contains invalid navigation",i+1)
   }
   initialized[s.Actor]=true
  case OpFill:
   if !initialized[s.Actor]||!validSelector.MatchString(s.Selector)||!validKey.MatchString(s.SecretKey)||
    s.Path!=""||s.ExpectedText!=""||s.ChallengeKind!="" {
    return fmt.Errorf("step %d has invalid secret fill",i+1)
   }
  case OpClick:
   if !initialized[s.Actor]||!validSelector.MatchString(s.Selector)||
    s.Path!=""||s.SecretKey!=""||s.ExpectedText!=""||s.ChallengeKind!="" {
    return fmt.Errorf("step %d has invalid click",i+1)
   }
  case OpAssert:
   if !initialized[s.Actor]||len(s.ExpectedText)<1||len(s.ExpectedText)>80||
    strings.ContainsAny(s.ExpectedText,"\r\n")||s.Selector!=""||
    s.Path!=""||s.SecretKey!=""||s.ChallengeKind!=""{
    return fmt.Errorf("step %d has invalid assertion",i+1)
   }
  case OpHandoff:
   if !initialized[s.Actor]||!(s.ChallengeKind=="mfa"||s.ChallengeKind=="passkey"||
    s.ChallengeKind=="anti_bot")||s.Selector!=""||s.Path!=""||s.SecretKey!=""||s.ExpectedText!=""{
    return fmt.Errorf("step %d has invalid operator handoff",i+1)
   }
  default:return fmt.Errorf("step %d has unsupported action",i+1)
  }
 }
 return nil
}
func allowedURL(current,origin string)bool{
 u,err:=url.Parse(current)
 return err==nil&&u!=nil&&u.User==nil&&u.Scheme=="http"&&
  "http://"+u.Host==origin
}
func proof(actor,action,state string,seq int)string{
 h:=sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s",seq,actor,action,state)))
 return hex.EncodeToString(h[:])
}
// Run executes a bounded trusted plan in one isolated browser per actor.
// A real browser factory must independently enforce egress restrictions;
// post-action URL checks are a second layer, not a network sandbox.
func Run(ctx context.Context,p Plan,factory Factory,secrets Secrets,operator Handoff)(Result,error){
 if err:=Validate(p);err!=nil{return Result{},err}
 if factory==nil{return Result{},errors.New("trusted browser factory missing")}
 origin,_:=Origin(p.Origin)
 sessions:=map[string]Browser{}
 defer func(){for _,b:=range sessions{b.Close()}}()
 result:=Result{Outcome:"completed_local_browser_fixture",Events:[]Event{},
  Disclaimer:"Completed actions occurred only in isolated numeric-loopback browser fixtures. A step hash is a local activity fingerprint, not independently signed security evidence."}
 for i,s:=range p.Steps{
  if err:=ctx.Err();err!=nil{return Result{},err}
  b:=sessions[s.Actor]
  if b==nil{
   var err error
   b,err=factory.New(ctx,s.Actor,origin)
   if err!=nil{return Result{},errors.New("trusted local browser could not start")}
   if b==nil{return Result{},errors.New("browser factory returned no session")}
   sessions[s.Actor]=b
  }
  // Full raw exception data may include page text or secrets; never expose
  // it across this boundary.
  switch s.Op{
  case OpNavigate:
   if err:=b.Navigate(ctx,origin+s.Path);err!=nil{return Result{},fmt.Errorf("step %d: local navigation failed",i+1)}
  case OpFill:
   if secrets==nil{return Result{},errors.New("trusted secret provider required")}
   value,err:=secrets.Resolve(ctx,s.Actor,s.SecretKey)
   if err!=nil||len(value)==0||len(value)>256{return Result{},errors.New("trusted secret unavailable")}
   if err:=b.Fill(ctx,s.Selector,value);err!=nil{return Result{},fmt.Errorf("step %d: local field fill failed",i+1)}
   value="" // Never return, serialize, or log submitted account material.
  case OpClick:
   if err:=b.Click(ctx,s.Selector);err!=nil{return Result{},fmt.Errorf("step %d: local click failed",i+1)}
  case OpAssert:
   ok,err:=b.Contains(ctx,s.ExpectedText)
   if err!=nil||!ok{return Result{},fmt.Errorf("step %d: local assertion failed",i+1)}
  case OpHandoff:
   if operator==nil{return Result{},fmt.Errorf("step %d requires external operator handoff",i+1)}
   approvalCtx,cancel:=context.WithTimeout(ctx,2*time.Minute)
   err:=operator.Authorize(approvalCtx,s.Actor,s.ChallengeKind)
   cancel()
   if err!=nil{return Result{},fmt.Errorf("step %d: operator handoff not completed",i+1)}
  }
  current,err:=b.CurrentURL(ctx)
  if err!=nil||!allowedURL(current,origin){return Result{},fmt.Errorf("step %d: browser left approved local origin",i+1)}
  result.Events=append(result.Events,Event{
   Seq:i+1,Actor:s.Actor,Action:s.Op,Outcome:"succeeded",
   EvidenceSHA256:proof(s.Actor,s.Op,"succeeded",i+1),
  })
  result.StepsCompleted++
 }
 result.Actors=len(sessions)
 return result,nil
}
