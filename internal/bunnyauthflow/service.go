// Package bunnyauthflow implements a self-contained, local-only
// registration, email-OTP and authenticated-session fixture.
// It is not a general-purpose account creator or CAPTCHA solver.
package bunnyauthflow

import (
 "crypto/rand"
 "crypto/subtle"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "math/big"
 "net/http"
 "regexp"
 "strings"
 "sync"
 "time"
)

const Sender = "no-reply@bunnymind.test"
const MaxAttempts=3
const MaxAccounts=8
const OTPExpiry=5*time.Minute
var allowedEmail=regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{1,60}@example[.]test$`)
var codeRE=regexp.MustCompile(`\b[0-9]{6}\b`)
type Message struct {
 From string
 To string
 Subject string
 Body string
}
type Mailbox struct {
 mu sync.Mutex
 messages map[string][]Message
}
func NewMailbox()*Mailbox{return &Mailbox{messages:make(map[string][]Message)}}
func (m *Mailbox) deliver(to,code string){
 m.mu.Lock();defer m.mu.Unlock()
 m.messages[to]=append(m.messages[to],Message{
  From:Sender,To:to,Subject:"BunnyMind test-account verification",
  Body:"Your synthetic verification code is "+code+". It expires in five minutes.",
 })
}
// Last is accessible to a trusted in-process test operator only. The fixture
// has no HTTP route to list messages, and agent-facing outputs omit message
// bodies and OTP codes.
func (m *Mailbox) Last(email string)(Message,bool){
 m.mu.Lock();defer m.mu.Unlock()
 list:=m.messages[email]
 if len(list)==0{return Message{},false}
 return list[len(list)-1],true
}
func ExtractCode(msg Message,email string)(string,error){
 if msg.From!=Sender||msg.To!=email{return "",errors.New("unexpected local message sender or recipient")}
 matches:=codeRE.FindAllString(msg.Body,-1)
 if len(matches)!=1{return "",errors.New("message must contain exactly one six-digit code")}
 return matches[0],nil
}
type account struct {
 email string
 id string
 marker string
 verified bool
 otp string
 otpExpires time.Time
 attempts int
}
type Service struct {
 mu sync.Mutex
 accounts map[string]*account
 sessions map[string]string
 mailbox *Mailbox
 unsafeForeignRead bool
 now func()time.Time
}
func NewService(mailbox *Mailbox, unsafeForeignRead bool)*Service {
 return &Service{
  accounts:map[string]*account{},sessions:map[string]string{},
  mailbox:mailbox,unsafeForeignRead:unsafeForeignRead,now:time.Now,
 }
}
func secureHex(bytes int)(string,error){
 b:=make([]byte,bytes)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return hex.EncodeToString(b),nil
}
func otpCode()(string,error){
 n,err:=rand.Int(rand.Reader,big.NewInt(1000000))
 if err!=nil{return "",err}
 return fmt.Sprintf("%06d",n.Int64()),nil
}
func (s *Service) Handler()http.Handler{
 mux:=http.NewServeMux()
 mux.HandleFunc("POST /register",s.register)
 mux.HandleFunc("POST /session/request",s.requestSession)
 mux.HandleFunc("POST /session/verify",s.verify)
 mux.HandleFunc("POST /session/rotate",s.rotate)
 mux.HandleFunc("POST /session/logout",s.logout)
 mux.HandleFunc("GET /me",s.me)
 mux.HandleFunc("GET /resource/{id}",s.resource)
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("X-Content-Type-Options","nosniff")
  mux.ServeHTTP(w,r)
 })
}
type mailRequest struct {Email string `json:"email"`}
type codeRequest struct {Email string `json:"email"`;Code string `json:"code"`}
func decode(r *http.Request,v any)bool{
 if r.Body==nil{return false}
 d:=json.NewDecoder(io.LimitReader(r.Body,4097))
 d.DisallowUnknownFields()
 if err:=d.Decode(v);err!=nil{return false}
 var more any
 return d.Decode(&more)==io.EOF
}
func respond(w http.ResponseWriter,status int,v any){
 w.Header().Set("Content-Type","application/json")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(v)
}
func deny(w http.ResponseWriter,status int){respond(w,status,map[string]string{"status":"denied"})}
func (s *Service) createChallenge(a *account)error{
 code,err:=otpCode()
 if err!=nil{return err}
 a.otp=code;a.otpExpires=s.now().Add(OTPExpiry);a.attempts=0
 s.mailbox.deliver(a.email,code)
 return nil
}
func (s *Service) register(w http.ResponseWriter,r *http.Request){
 var args mailRequest
 if !decode(r,&args)||!allowedEmail.MatchString(args.Email){deny(w,400);return}
 s.mu.Lock();defer s.mu.Unlock()
 if _,exists:=s.accounts[args.Email];exists{deny(w,409);return}
 if len(s.accounts)>=MaxAccounts{deny(w,429);return}
 id,err:=secureHex(12);if err!=nil{deny(w,500);return}
 marker,err:=secureHex(24);if err!=nil{deny(w,500);return}
 a:=&account{email:args.Email,id:id,marker:marker}
 if err=s.createChallenge(a);err!=nil{deny(w,500);return}
 s.accounts[a.email]=a
 respond(w,202,map[string]string{"status":"verification_sent"})
}
func (s *Service) requestSession(w http.ResponseWriter,r *http.Request){
 var args mailRequest
 if !decode(r,&args)||!allowedEmail.MatchString(args.Email){deny(w,400);return}
 s.mu.Lock();defer s.mu.Unlock()
 a,exists:=s.accounts[args.Email]
 if !exists||!a.verified{deny(w,403);return}
 if err:=s.createChallenge(a);err!=nil{deny(w,500);return}
 respond(w,202,map[string]string{"status":"verification_sent"})
}
func (s *Service) verify(w http.ResponseWriter,r *http.Request){
 var args codeRequest
 if !decode(r,&args)||!allowedEmail.MatchString(args.Email)||!codeRE.MatchString(args.Code)||len(args.Code)!=6{deny(w,400);return}
 s.mu.Lock();defer s.mu.Unlock()
 a,exists:=s.accounts[args.Email]
 if !exists||a.otp==""||!s.now().Before(a.otpExpires)||a.attempts>=MaxAttempts{deny(w,401);return}
 a.attempts++
 if subtle.ConstantTimeCompare([]byte(a.otp),[]byte(args.Code))!=1{deny(w,401);return}
 // One-time use: consume the code before any session is issued.
 a.otp="";a.otpExpires=time.Time{};a.verified=true
 token,err:=secureHex(32);if err!=nil{deny(w,500);return}
 s.sessions[token]=a.email
 respond(w,200,map[string]string{"token":token,"resource_id":a.id})
}
func bearer(r *http.Request)string{
 const prefix="Bearer "
 h:=r.Header.Get("Authorization")
 if !strings.HasPrefix(h,prefix){return ""}
 return strings.TrimPrefix(h,prefix)
}
func (s *Service) sessionAccount(r *http.Request)*account{
 token:=bearer(r)
 email,ok:=s.sessions[token]
 if !ok||token==""{return nil}
 return s.accounts[email]
}
func (s *Service) rotate(w http.ResponseWriter,r *http.Request){
 s.mu.Lock();defer s.mu.Unlock()
 a:=s.sessionAccount(r)
 if a==nil{deny(w,401);return}
 newToken,err:=secureHex(32);if err!=nil{deny(w,500);return}
 delete(s.sessions,bearer(r));s.sessions[newToken]=a.email
 respond(w,200,map[string]string{"token":newToken})
}
func (s *Service) logout(w http.ResponseWriter,r *http.Request){
 s.mu.Lock();defer s.mu.Unlock()
 if s.sessionAccount(r)==nil{deny(w,401);return}
 delete(s.sessions,bearer(r))
 respond(w,200,map[string]string{"status":"logged_out"})
}
func (s *Service) me(w http.ResponseWriter,r *http.Request){
 s.mu.Lock();defer s.mu.Unlock()
 a:=s.sessionAccount(r)
 if a==nil{deny(w,401);return}
 respond(w,200,map[string]string{"resource_id":a.id})
}
func (s *Service) resource(w http.ResponseWriter,r *http.Request){
 s.mu.Lock();defer s.mu.Unlock()
 current:=s.sessionAccount(r)
 if current==nil{deny(w,401);return}
 targetID:=r.PathValue("id")
 for _,a:=range s.accounts{
  if a.id!=targetID{continue}
  if current.id!=targetID&&!s.unsafeForeignRead{deny(w,403);return}
  respond(w,200,map[string]string{"marker":a.marker})
  return
 }
 deny(w,404)
}
