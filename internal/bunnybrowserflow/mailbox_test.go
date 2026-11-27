package bunnybrowserflow

import (
 "context"
 "errors"
 "strings"
 "testing"
 "time"
)

type fakeInbox struct {
 messages map[string][]InboxMessage
 calls int
}
func (i *fakeInbox) Recent(ctx context.Context,c MailboxConfig,actor,password string)([]InboxMessage,error){
 i.calls++
 if password!="test-password-123" {return nil,errors.New("bad trusted inbox password")}
 return i.messages[actor],nil
}
type mailboxOtherSecrets struct{}
func (mailboxOtherSecrets) Resolve(ctx context.Context,actor,key string)(string,error){
 if key=="imap_password"{return "test-password-123",nil}
 if key=="email"{return "actor@example.test",nil}
 return "",errors.New("unknown secret")
}
func sampleMailConfig()MailboxConfig{
 return MailboxConfig{Host:"imap.example.com",Port:993,Boxes:map[string]MailboxActor{
  "owner":{Address:"owner@example.test",Sender:"verify@example.test"},
  "peer":{Address:"peer@example.test",Sender:"verify@example.test"},
 }}
}
func TestMailboxConfigRequiresIsolatedTLSIdentities(t *testing.T){
 c:=sampleMailConfig()
 if err:=validateMailboxConfig(c);err!=nil{t.Fatal(err)}
 c.Port=143
 if err:=validateMailboxConfig(c);err==nil{t.Fatal("plain IMAP permitted")}
 c=sampleMailConfig();c.Host="127.0.0.1"
 if err:=validateMailboxConfig(c);err==nil{t.Fatal("private literal IMAP allowed")}
 c=sampleMailConfig();c.Boxes["peer"]=c.Boxes["owner"]
 if err:=validateMailboxConfig(c);err==nil{t.Fatal("shared mailbox identity permitted")}
}
func TestOTPRequiresMatchedSenderRecipientAndFreshness(t *testing.T){
 now:=time.Now().UTC()
 good:=InboxMessage{UID:12,From:"verify@example.test",To:[]string{"owner@example.test"},
  Subject:"Your verification code",Received:now,Body:"Your verification code is 654321."}
 box:=sampleMailConfig().Boxes["owner"]
 code,ok:=verifiedCode(good,box,now.Add(-time.Second),0)
 if !ok||code!="654321"{t.Fatalf("good verification rejected %v %s",ok,code)}
 tests:=[]InboxMessage{
  {UID:12,From:"other@example.test",To:good.To,Subject:good.Subject,Received:now,Body:good.Body},
  {UID:12,From:good.From,To:[]string{"peer@example.test"},Subject:good.Subject,Received:now,Body:good.Body},
  {UID:12,From:good.From,To:good.To,Subject:good.Subject,Received:now.Add(-time.Hour),Body:good.Body},
  {UID:12,From:good.From,To:good.To,Subject:good.Subject,Received:now,Body:"Your verification code is 654321 or 777777."},
  {UID:12,From:good.From,To:good.To,Subject:"Special offer",Received:now,Body:"Your number: 654321"},
 }
 for n,m:=range tests{if _,ok:=verifiedCode(m,box,now.Add(-time.Second),0);ok{t.Fatalf("unsafe inbox message %d accepted",n)}}
 if _,ok:=verifiedCode(good,box,now.Add(-time.Second),12);ok{t.Fatal("replay UID accepted")}
}
func TestTrustedMailboxOTPOnlyConsumedOnceAndNeverLogged(t *testing.T){
 now:=time.Now().UTC()
 inbox:=&fakeInbox{messages:map[string][]InboxMessage{
  "owner":{{UID:35,From:"verify@example.test",To:[]string{"owner@example.test"},
   Subject:"Verification code",Received:now.Add(1*time.Second),Body:"Code: 345678"}},
 }}
 provider,err:=NewTrustedMailboxSecrets(sampleMailConfig(),inbox,mailboxOtherSecrets{})
 if err!=nil{t.Fatal(err)}
 provider.MarkCodeRequested("owner")
 code,err:=provider.Resolve(context.Background(),"owner","otp")
 if err!=nil||code!="345678"{t.Fatalf("code extraction failed %s %v",code,err)}
 if _,err:=provider.Resolve(context.Background(),"owner","otp");err==nil{t.Fatal("reused code")}
 if strings.Contains(provider.String(),"345678")||strings.Contains(provider.String(),"owner@example.test"){
  t.Fatal("trusted adapter leaked mailbox secrets")
 }
}
func TestTrustedMailboxMissingActorOrCodeFailsClosed(t *testing.T){
 inbox:=&fakeInbox{messages:map[string][]InboxMessage{}}
 provider,_:=NewTrustedMailboxSecrets(sampleMailConfig(),inbox,mailboxOtherSecrets{})
 if _,err:=provider.Resolve(context.Background(),"owner","otp");err==nil{t.Fatal("read without request timestamp")}
 ctx,cancel:=context.WithCancel(context.Background())
 provider.MarkCodeRequested("owner")
 cancel()
 if _,err:=provider.Resolve(ctx,"owner","otp");err==nil{t.Fatal("ignored cancellation")}
}
