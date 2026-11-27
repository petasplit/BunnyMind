package bunnyauthflow

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "net/http"
 "time"

 "github.com/enowdev/antares/internal/bunnyidentity"
 "github.com/enowdev/antares/internal/bunnychallenge"
)

// RegistrationPort is supplied by trusted application code, never by a
// model-selected URL. Future adapters must have their own authorization,
// egress, rate-limit, and credential-isolation boundary.
type RegistrationPort interface {
 Register(ctx context.Context,email string)error
 ExchangeEmailCode(ctx context.Context,email,code string)(token,resource string,err error)
}
type InboxPort interface {
 Latest(ctx context.Context,email string)(Message,error)
}
type Coordinator struct{
 Registration RegistrationPort
 Inbox InboxPort
 Sessions *bunnyidentity.Vault
 Challenges *bunnychallenge.Broker
}
type Enrollment struct{
 Actor string `json:"actor"`
 ResourceID string `json:"resource_id"`
 CodeConsumed bool `json:"code_consumed"`
 SessionVaulted bool `json:"session_vaulted"`
 ChallengeCompleted bool `json:"challenge_completed"`
}
// Provision registers a synthetic account, reads the trusted inbox,
// extracts the code, exchanges it for a bearer token, and stores that token
// privately in a per-persona memory vault. No email/code/token is returned.
func (c Coordinator) Provision(ctx context.Context,actor,email string)(Enrollment,error){
 if c.Registration==nil||c.Inbox==nil||c.Sessions==nil{
  return Enrollment{},errors.New("trusted auth adapter, inbox and vault are required")
 }
 if !allowedEmail.MatchString(email){return Enrollment{},errors.New("only synthetic example.test identities are permitted")}
 challengeID:=""
 if c.Challenges!=nil{
  ticket,err:=c.Challenges.Open(actor,bunnychallenge.EmailOTP,OTPExpiry)
  if err!=nil{return Enrollment{},err}
  challengeID=ticket.ID
 }
 if err:=c.Registration.Register(ctx,email);err!=nil{return Enrollment{},err}
 msg,err:=c.Inbox.Latest(ctx,email);if err!=nil{return Enrollment{},err}
 code,err:=ExtractCode(msg,email);if err!=nil{return Enrollment{},err}
 token,resource,err:=c.Registration.ExchangeEmailCode(ctx,email,code)
 if err!=nil{return Enrollment{},err}
 if err:=c.Sessions.Add(actor,token,resource,15*time.Minute);err!=nil{
  return Enrollment{},errors.New("synthetic session could not be stored")
 }
 challengeCompleted:=false
 if c.Challenges!=nil{
  // A high-entropy successful session grant is safe to hash. Never hash
  // six-digit OTPs or put the OTP itself into challenge metadata.
  digest:=sha256.Sum256([]byte(token))
  proof:=hex.EncodeToString(digest[:])
  if _,err:=c.Challenges.EmailCompleted(challengeID,proof);err!=nil{
   c.Sessions.Revoke(actor)
   return Enrollment{},errors.New("trusted challenge could not be completed")
  }
  challengeCompleted=true
 }
 return Enrollment{Actor:actor,ResourceID:resource,CodeConsumed:true,SessionVaulted:true,ChallengeCompleted:challengeCompleted},nil
}

// LocalRegistrationPort is the only adapter implemented in v0.18.
// Its underlying client is restricted to an already-running numeric-loopback
// fixture by newLocalClient and cannot be constructed from an agent tool URL.
type LocalRegistrationPort struct{client *localClient}
func (a LocalRegistrationPort) Register(ctx context.Context,email string)error{
 if a.client==nil{return errors.New("no trusted local account transport")}
 st,_,err:=a.client.request(ctx,http.MethodPost,"/register","",mailRequest{Email:email})
 return mustStatus(st,http.StatusAccepted,err)
}
func (a LocalRegistrationPort) ExchangeEmailCode(ctx context.Context,email,code string)(string,string,error){
 if a.client==nil{return "","",errors.New("no trusted local account transport")}
 st,result,err:=a.client.request(ctx,http.MethodPost,"/session/verify","",codeRequest{Email:email,Code:code})
 if err=mustStatus(st,http.StatusOK,err);err!=nil{return "","",err}
 if len(result["token"])<32||len(result["resource_id"])<12{return "","",errors.New("test session not established")}
 return result["token"],result["resource_id"],nil
}
// Latest has no public HTTP inbox endpoint. It is a private, trusted
// in-process fixture method for the enrollment coordinator.
func (m *Mailbox) Latest(_ context.Context,email string)(Message,error){
 v,ok:=m.Last(email)
 if !ok{return Message{},errors.New("local mailbox contains no verification message for account")}
 return v,nil
}
