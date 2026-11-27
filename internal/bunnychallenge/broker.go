// Package bunnychallenge manages bounded authentication challenge tickets.
// It never processes raw OTPs or executes browser anti-bot interactions.
package bunnychallenge

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "regexp"
 "sync"
 "time"
)

const MaxTickets=32
const MaxAttempts=3
const MaxChallengeWindow=10*time.Minute
type Kind string
const (
 EmailOTP Kind="email_otp"
 TOTP Kind="totp"
 Passkey Kind="passkey"
 PushMFA Kind="push_mfa"
 AntiBot Kind="anti_bot"
)
const (
 PendingTrustedOTP="pending_trusted_otp"
 PendingOperator="pending_operator"
 Completed="completed"
 Rejected="rejected"
 Expired="expired"
)
var actorRx=regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
var digestRx=regexp.MustCompile(`^[0-9a-f]{64}$`)
type ticket struct {
 ID string
 Actor string
 Kind Kind
 State string
 Created time.Time
 Expires time.Time
 AttemptsLeft int
 ReceiptSHA256 string
 OperatorRef string
}
type View struct {
 ID string `json:"id"`
 Actor string `json:"actor"`
 Kind Kind `json:"kind"`
 State string `json:"state"`
 AttemptsLeft int `json:"attempts_left"`
 ExpiresAt string `json:"expires_at"`
 EvidencePresent bool `json:"evidence_present"`
 OperatorApproved bool `json:"operator_approved"`
}
type SignedDecision struct {
 TicketID string `json:"ticket_id"`
 Decision string `json:"decision"`
 SignedAt string `json:"signed_at"`
 Signature string `json:"signature"`
}
type Broker struct {
 mu sync.Mutex
 now func()time.Time
 tickets map[string]*ticket
 operatorPublic ed25519.PublicKey
}
func New(operatorPublic ed25519.PublicKey)(*Broker,error){
 if len(operatorPublic)!=0&&len(operatorPublic)!=ed25519.PublicKeySize{return nil,errors.New("operator public key must be Ed25519")}
 return &Broker{now:time.Now,tickets:map[string]*ticket{},operatorPublic:append(ed25519.PublicKey(nil),operatorPublic...)},nil
}
func randomID()(string,error){
 b:=make([]byte,16)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return hex.EncodeToString(b),nil
}
func kindValid(k Kind)bool{
 switch k{case EmailOTP,TOTP,Passkey,PushMFA,AntiBot:return true;default:return false}
}
func asView(t *ticket)View{
 return View{ID:t.ID,Actor:t.Actor,Kind:t.Kind,State:t.State,AttemptsLeft:t.AttemptsLeft,
 ExpiresAt:t.Expires.UTC().Format(time.RFC3339Nano),
 EvidencePresent:t.ReceiptSHA256!="",OperatorApproved:t.OperatorRef!=""}
}
func (b *Broker) nowUTC()time.Time{
 if b.now!=nil{return b.now().UTC()}
 return time.Now().UTC()
}
func (b *Broker) get(id string)(*ticket,error){
 t,ok:=b.tickets[id]
 if !ok{return nil,errors.New("unknown challenge ticket")}
 if b.nowUTC().After(t.Expires)&&t.State!=Completed&&t.State!=Rejected{
  t.State=Expired;t.AttemptsLeft=0
 }
 return t,nil
}
func (b *Broker) Open(actor string,k Kind,ttl time.Duration)(View,error){
 if !actorRx.MatchString(actor)||!kindValid(k){return View{},errors.New("invalid actor or challenge type")}
 if ttl<15*time.Second||ttl>MaxChallengeWindow{return View{},errors.New("challenge lease must be 15 seconds..10 minutes")}
 b.mu.Lock();defer b.mu.Unlock()
 if len(b.tickets)>=MaxTickets{return View{},errors.New("challenge ticket budget exhausted")}
 id,err:=randomID();if err!=nil{return View{},err}
 state:=PendingOperator
 if k==EmailOTP{state=PendingTrustedOTP}
 ticket:=&ticket{ID:id,Actor:actor,Kind:k,State:state,Created:b.nowUTC(),
  Expires:b.nowUTC().Add(ttl),AttemptsLeft:MaxAttempts}
 b.tickets[id]=ticket
 return asView(ticket),nil
}
func (b *Broker) Status(id string)(View,error){
 b.mu.Lock();defer b.mu.Unlock()
 t,err:=b.get(id);if err!=nil{return View{},err}
 return asView(t),nil
}
// EmailFailed consumes a single failed code-submission attempt. It only
// tracks failure metadata; raw OTPs and messages never enter the broker.
func (b *Broker) EmailFailed(id string)(View,error){
 b.mu.Lock();defer b.mu.Unlock()
 t,err:=b.get(id);if err!=nil{return View{},err}
 if t.Kind!=EmailOTP||t.State!=PendingTrustedOTP{return View{},errors.New("email challenge is not pending")}
 t.AttemptsLeft--
 if t.AttemptsLeft==0{t.State=Rejected}
 return asView(t),nil
}
// EmailCompleted accepts a *trusted adapter's* receipt digest after
// successfully exchanging the OTP. Digest must not be of a six-digit code;
// use a high-entropy session result so the digest cannot reveal the OTP.
func (b *Broker) EmailCompleted(id,receiptSHA256 string)(View,error){
 if !digestRx.MatchString(receiptSHA256){return View{},errors.New("trusted email completion requires a SHA-256 receipt digest")}
 b.mu.Lock();defer b.mu.Unlock()
 t,err:=b.get(id);if err!=nil{return View{},err}
 if t.Kind!=EmailOTP||t.State!=PendingTrustedOTP{return View{},errors.New("email OTP ticket not pending")}
 t.State=Completed;t.ReceiptSHA256=receiptSHA256;t.AttemptsLeft=0
 return asView(t),nil
}
func signingMessage(d SignedDecision)([]byte,error){
 if d.Decision!="approve"&&d.Decision!="reject"{return nil,errors.New("invalid operator decision")}
 if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(d.TicketID){return nil,errors.New("invalid ticket ID")}
 if _,err:=time.Parse(time.RFC3339Nano,d.SignedAt);err!=nil{return nil,errors.New("invalid signature timestamp")}
 return json.Marshal(struct{
  ID string `json:"id"`
  Decision string `json:"decision"`
  SignedAt string `json:"signed_at"`
 }{d.TicketID,d.Decision,d.SignedAt})
}
// SignDecision is intended ONLY for an independent trusted operator tool.
// It is not exported as an Antares agent tool or exposed to the model.
func SignDecision(private ed25519.PrivateKey,id,decision string,at time.Time)(SignedDecision,error){
 if len(private)!=ed25519.PrivateKeySize{return SignedDecision{},errors.New("invalid operator private key")}
 d:=SignedDecision{TicketID:id,Decision:decision,SignedAt:at.UTC().Format(time.RFC3339Nano)}
 payload,err:=signingMessage(d);if err!=nil{return SignedDecision{},err}
 d.Signature=base64.StdEncoding.EncodeToString(ed25519.Sign(private,payload))
 return d,nil
}
// CompleteHuman requires a signature from the *configured* operator
// authority. Models and plugins cannot self-approve a ticket by supplying
// an arbitrary code or by setting the state in a tool argument.
func (b *Broker) CompleteHuman(d SignedDecision)(View,error){
 payload,err:=signingMessage(d);if err!=nil{return View{},err}
 sig,err:=base64.StdEncoding.Strict().DecodeString(d.Signature)
 if err!=nil||len(sig)!=ed25519.SignatureSize{return View{},errors.New("invalid signed approval encoding")}
 b.mu.Lock();defer b.mu.Unlock()
 if len(b.operatorPublic)!=ed25519.PublicKeySize{return View{},errors.New("operator signing authority not configured")}
 t,err:=b.get(d.TicketID);if err!=nil{return View{},err}
 if t.Kind==EmailOTP||t.State!=PendingOperator{return View{},errors.New("human challenge not pending")}
 signedAt,err:=time.Parse(time.RFC3339Nano,d.SignedAt)
 if err!=nil||signedAt.Before(t.Created)||signedAt.After(b.nowUTC().Add(30*time.Second))||signedAt.After(t.Expires){
  return View{},errors.New("operator approval timestamp outside valid ticket window")
 }
 if !ed25519.Verify(b.operatorPublic,payload,sig){return View{},errors.New("signature not from configured operator")}
 if d.Decision=="approve"{t.State=Completed;t.OperatorRef=hex.EncodeToString(b.operatorPublic[:8])
 }else{t.State=Rejected}
 t.AttemptsLeft=0
 return asView(t),nil
}
func (b *Broker) Count()int{
 b.mu.Lock();defer b.mu.Unlock()
 return len(b.tickets)
}
func (b *Broker) Report()string{
 return fmt.Sprintf("BunnyMind authentication challenge broker (%d redacted tickets)",b.Count())
}
func SignerPublicDigest(pub ed25519.PublicKey)string{
 h:=sha256.Sum256(pub)
 return hex.EncodeToString(h[:])
}
