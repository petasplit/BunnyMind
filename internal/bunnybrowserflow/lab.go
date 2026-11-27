package bunnybrowserflow

import (
 "context"
 "crypto/rand"
 "crypto/subtle"
 "embed"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "net/http/httptest"
 "regexp"
 "strings"
 "sync"
 "time"
)

//go:embed lab.html
var labHTML embed.FS

var fixtureEmail=regexp.MustCompile(`^(owner|peer)_[0-9a-f]{16}@example[.]test$`)
type signupRequest struct {
 Email string `json:"email"`
 Code string `json:"code"`
}
type labAccount struct{actor,code string;verified bool}
type labState struct {
 mu sync.Mutex
 registered map[string]*labAccount
 sessions map[string]string
 emails map[string]string
}
func newLabState()*labState {
 return &labState{
  registered:map[string]*labAccount{},
  sessions:map[string]string{},
  emails:map[string]string{},
 }
}
func randomHex(n int)(string,error){
 b:=make([]byte,n)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return hex.EncodeToString(b),nil
}
func (s *labState) provisionActors()error{
 for _,actor:=range []string{"owner","peer"}{
  suffix,err:=randomHex(8);if err!=nil{return err}
  s.emails[actor]=actor+"_"+suffix+"@example.test"
 }
 return nil
}
func parseFixtureRequest(r *http.Request)(signupRequest,bool){
 if r.Header.Get("Content-Type")!="application/json"{return signupRequest{},false}
 var q signupRequest
 d:=json.NewDecoder(io.LimitReader(r.Body,1024))
 d.DisallowUnknownFields()
 if err:=d.Decode(&q);err!=nil{return signupRequest{},false}
 var more any
 if d.Decode(&more)!=io.EOF{return signupRequest{},false}
 return q,true
}
func jsonResponse(w http.ResponseWriter,status int,body any){
 w.Header().Set("Cache-Control","no-store")
 w.Header().Set("Content-Type","application/json")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(body)
}
func (s *labState) Handler()http.Handler{
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /",func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/"{http.NotFound(w,r);return}
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("Content-Type","text/html; charset=utf-8")
  page,err:=labHTML.ReadFile("lab.html")
  if err!=nil{http.Error(w,"fixture unavailable",500);return}
  _,_=w.Write(page)
 })
 mux.HandleFunc("POST /signup",func(w http.ResponseWriter,r *http.Request){
  q,ok:=parseFixtureRequest(r)
  if !ok||!fixtureEmail.MatchString(q.Email)||q.Code!=""{
   jsonResponse(w,400,map[string]string{"status":"denied"});return
  }
  s.mu.Lock();defer s.mu.Unlock()
  actor:=""
  for id,email:=range s.emails{if email==q.Email{actor=id;break}}
  if actor==""||s.registered[q.Email]!=nil{
   jsonResponse(w,403,map[string]string{"status":"denied"});return
  }
  // Securely generated disposable one-time code never leaves this private
  // fixture through agent-facing responses or a public mailbox endpoint.
  raw,err:=randomHex(4)
  if err!=nil{jsonResponse(w,500,map[string]string{"status":"error"});return}
  s.registered[q.Email]=&labAccount{actor:actor,code:raw}
  jsonResponse(w,202,map[string]string{"status":"verification_required"})
 })
 mux.HandleFunc("POST /verify",func(w http.ResponseWriter,r *http.Request){
  q,ok:=parseFixtureRequest(r)
  if !ok||!fixtureEmail.MatchString(q.Email)||len(q.Code)!=8{
   jsonResponse(w,400,map[string]string{"status":"denied"});return
  }
  s.mu.Lock();defer s.mu.Unlock()
  acct:=s.registered[q.Email]
  if acct==nil||acct.verified||subtle.ConstantTimeCompare([]byte(acct.code),[]byte(q.Code))!=1{
   jsonResponse(w,401,map[string]string{"status":"denied"});return
  }
  token,err:=randomHex(32)
  if err!=nil{jsonResponse(w,500,map[string]string{"status":"error"});return}
  acct.code="" // One-time use before issuing the session.
  acct.verified=true
  s.sessions[token]=acct.actor
  http.SetCookie(w,&http.Cookie{
   Name:"bm_lab_session",Value:token,Path:"/",HttpOnly:true,
   SameSite:http.SameSiteStrictMode,MaxAge:600,
  })
  jsonResponse(w,200,map[string]string{"status":"ok"})
 })
 mux.HandleFunc("GET /whoami",func(w http.ResponseWriter,r *http.Request){
  ck,err:=r.Cookie("bm_lab_session")
  if err!=nil{jsonResponse(w,401,map[string]string{"status":"denied"});return}
  s.mu.Lock();actor:=s.sessions[ck.Value];s.mu.Unlock()
  if actor==""{jsonResponse(w,401,map[string]string{"status":"denied"});return}
  jsonResponse(w,200,map[string]string{"actor":actor})
 })
 mux.HandleFunc("POST /logout",func(w http.ResponseWriter,r *http.Request){
  ck,err:=r.Cookie("bm_lab_session")
  if err!=nil{jsonResponse(w,401,map[string]string{"status":"denied"});return}
  s.mu.Lock()
  actor:=s.sessions[ck.Value]
  delete(s.sessions,ck.Value)
  s.mu.Unlock()
  if actor==""{jsonResponse(w,401,map[string]string{"status":"denied"});return}
  http.SetCookie(w,&http.Cookie{Name:"bm_lab_session",Path:"/",Value:"",MaxAge:-1,HttpOnly:true})
  jsonResponse(w,200,map[string]string{"status":"ok"})
 })
 return mux
}
type fixtureSecrets struct{state *labState}
func (s fixtureSecrets) Resolve(ctx context.Context,actor,key string)(string,error){
 if err:=ctx.Err();err!=nil{return "",err}
 s.state.mu.Lock();defer s.state.mu.Unlock()
 if key=="email" {
  if s.state.emails[actor]==""{return "",errors.New("unknown test identity")}
  return s.state.emails[actor],nil
 }
 if key=="otp" {
  acct:=s.state.registered[s.state.emails[actor]]
  if acct==nil||acct.code==""{return "",errors.New("trusted mailbox has no pending local code")}
  return acct.code,nil
 }
 return "",errors.New("unsupported secret reference")
}
func LocalPlan(origin string)Plan{
 var steps []Step
 for _,actor:=range []string{"owner","peer"}{
  steps=append(steps,
   Step{Actor:actor,Op:OpNavigate,Path:"/"},
   Step{Actor:actor,Op:OpFill,Selector:"#email",SecretKey:"email"},
   Step{Actor:actor,Op:OpClick,Selector:"#register"},
   Step{Actor:actor,Op:OpAssert,ExpectedText:"Verification required"},
   Step{Actor:actor,Op:OpFill,Selector:"#code",SecretKey:"otp"},
   Step{Actor:actor,Op:OpClick,Selector:"#verify"},
   Step{Actor:actor,Op:OpAssert,ExpectedText:"Signed in"},
   Step{Actor:actor,Op:OpClick,Selector:"#identity"},
   Step{Actor:actor,Op:OpAssert,ExpectedText:"Hello "+actor},
  )
 }
 return Plan{Origin:origin,Steps:steps}
}
// RunLab performs actual Chrome interactions against a disposable in-process
// HTTP site. No third-party URLs, credentials, mailboxes or user accounts are
// accepted or contacted. It proves local orchestration, not target security.
func RunLab(ctx context.Context)(Result,error){
 state:=newLabState()
 if err:=state.provisionActors();err!=nil{return Result{},errors.New("fixture identity generation failed")}
 server:=httptest.NewServer(state.Handler())
 defer server.Close()
 timeout,cancel:=context.WithTimeout(ctx,2*time.Minute)
 defer cancel()
 return Run(timeout,LocalPlan(server.URL),ChromiumFactory{},fixtureSecrets{state},nil)
}
