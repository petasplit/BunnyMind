package bunnychallenge

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "strings"
 "testing"
 "time"
)
func TestEmailChallengeSuccess(t *testing.T){
 b,_:=New(nil)
 v,err:=b.Open("owner",EmailOTP,time.Minute);if err!=nil{t.Fatal(err)}
 if v.State!=PendingTrustedOTP||v.AttemptsLeft!=3{t.Fatal("wrong ticket state")}
 if _,err=b.EmailCompleted(v.ID,strings.Repeat("a",64));err!=nil{t.Fatal(err)}
 after,_:=b.Status(v.ID)
 if after.State!=Completed||!after.EvidencePresent||after.OperatorApproved{t.Fatal("email completion incorrect")}
 if _,err:=b.EmailCompleted(v.ID,strings.Repeat("b",64));err==nil{t.Fatal("OTP ticket reused")}
}
func TestEmailFailuresAndBudget(t *testing.T){
 b,_:=New(nil)
 v,_:=b.Open("owner",EmailOTP,time.Minute)
 for i:=0;i<MaxAttempts;i++{
  out,err:=b.EmailFailed(v.ID);if err!=nil{t.Fatal(err)}
  if i==MaxAttempts-1&&out.State!=Rejected{t.Fatal("failure budget not enforced")}
 }
 if _,err:=b.EmailFailed(v.ID);err==nil{t.Fatal("failed challenge retried")}
}
func TestHumanMFARequiresPinnedSignature(t *testing.T){
 pub,priv,_:=ed25519.GenerateKey(rand.Reader)
 b,_:=New(pub)
 v,err:=b.Open("owner",Passkey,time.Minute);if err!=nil{t.Fatal(err)}
 if v.State!=PendingOperator{t.Fatal("human challenge not paused")}
 if _,err:=b.EmailCompleted(v.ID,strings.Repeat("a",64));err==nil{t.Fatal("human bypassed with email approval")}
 d,err:=SignDecision(priv,v.ID,"approve",time.Now());if err!=nil{t.Fatal(err)}
 resolved,err:=b.CompleteHuman(d)
 if err!=nil||resolved.State!=Completed||!resolved.OperatorApproved{t.Fatalf("%+v %v",resolved,err)}
 if _,err=b.CompleteHuman(d);err==nil{t.Fatal("approval replay accepted")}
}
func TestWrongOperatorCannotApprove(t *testing.T){
 pub,_,_:=ed25519.GenerateKey(rand.Reader)
 _,wrongPriv,_:=ed25519.GenerateKey(rand.Reader)
 b,_:=New(pub)
 v,_:=b.Open("owner",AntiBot,time.Minute)
 d,_:=SignDecision(wrongPriv,v.ID,"approve",time.Now())
 if _,err:=b.CompleteHuman(d);err==nil{t.Fatal("untrusted signing key accepted")}
}
func TestMissingOperatorFailsClosed(t *testing.T){
 b,_:=New(nil)
 _,priv,_:=ed25519.GenerateKey(rand.Reader)
 v,_:=b.Open("owner",PushMFA,time.Minute)
 d,_:=SignDecision(priv,v.ID,"approve",time.Now())
 if _,err:=b.CompleteHuman(d);err==nil{t.Fatal("missing operator configured")}
}
func TestExpiryStopsChallenge(t *testing.T){
 b,_:=New(nil)
 now:=time.Now().UTC()
 b.now=func()time.Time{return now}
 v,_:=b.Open("owner",EmailOTP,20*time.Second)
 now=now.Add(21*time.Second)
 s,err:=b.Status(v.ID)
 if err!=nil||s.State!=Expired{t.Fatalf("%+v %v",s,err)}
 if _,err=b.EmailCompleted(v.ID,strings.Repeat("a",64));err==nil{t.Fatal("expired challenge completed")}
}
func TestNoSecretMaterialInMetadata(t *testing.T){
 pub,priv,_:=ed25519.GenerateKey(rand.Reader)
 b,_:=New(pub)
 v,_:=b.Open("owner",TOTP,time.Minute)
 d,_:=SignDecision(priv,v.ID,"reject",time.Now())
 _,_ =b.CompleteHuman(d)
 after,_:=b.Status(v.ID)
 raw,_:=json.Marshal(after)
 if strings.Contains(string(raw),"123456")||strings.Contains(string(raw),"private")||strings.Contains(string(raw),d.Signature){
  t.Fatal("approval secrets leaked to status")
 }
}
func TestMaxTicketsAndInvalidIdentity(t *testing.T){
 b,_:=New(nil)
 if _,err:=b.Open("owner@real.com",EmailOTP,time.Minute);err==nil{t.Fatal("invalid actor accepted")}
 for i:=0;i<MaxTickets;i++{
  if _,err:=b.Open("owner",EmailOTP,time.Minute);err!=nil{t.Fatal(err)}
 }
 if _,err:=b.Open("foreign",EmailOTP,time.Minute);err==nil{t.Fatal("ticket quota bypassed")}
}
func TestHumanRejectsApprovalsFromOtherTickets(t *testing.T){
 pub,priv,_:=ed25519.GenerateKey(rand.Reader)
 b,_:=New(pub)
 a,_:=b.Open("owner",PushMFA,time.Minute)
 other,_:=b.Open("foreign",PushMFA,time.Minute)
 d,_:=SignDecision(priv,a.ID,"approve",time.Now())
 d.TicketID=other.ID
 if _,err:=b.CompleteHuman(d);err==nil{t.Fatal("rebound approval accepted")}
}
func TestCannotApproveExpiredHumanChallenge(t *testing.T){
 pub,priv,_:=ed25519.GenerateKey(rand.Reader)
 b,_:=New(pub)
 now:=time.Now().UTC()
 b.now=func()time.Time{return now}
 v,_:=b.Open("owner",AntiBot,20*time.Second)
 d,_:=SignDecision(priv,v.ID,"approve",now)
 now=now.Add(21*time.Second)
 if _,err:=b.CompleteHuman(d);err==nil{t.Fatal("expired human approval accepted")}
}
