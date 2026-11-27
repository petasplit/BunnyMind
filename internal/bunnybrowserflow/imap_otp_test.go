package bunnybrowserflow

import (
 "context"
 "net/netip"
 "testing"
 "time"

 "github.com/emersion/go-imap"
)
type fakeMailSecrets struct{}
func (fakeMailSecrets) Resolve(_ context.Context,actor,key string)(string,error){return "not-used-in-parse-test",nil}
func message(from,to,subject string,at time.Time)*imap.Message{
 return &imap.Message{
  Envelope:&imap.Envelope{
   Date:at,Subject:subject,
   From:[]*imap.Address{{MailboxName:from[:indexAt(from)],HostName:from[indexAt(from)+1:]}},
   To:[]*imap.Address{{MailboxName:to[:indexAt(to)],HostName:to[indexAt(to)+1:]}},
  },
 }
}
func indexAt(s string)int{
 for i,r:=range s{if r=='@'{return i}}
 return len(s)
}
func TestOnlyFreshAllowlistedVerificationEmailsAccepted(t *testing.T){
 now:=time.Now().UTC()
 m:=message("security@approved.example","test@operator.example","Verification",now)
 code,ok:=extractVerifiedCode("Your verification code: 739215", "security@approved.example","test@operator.example",m,now)
 if !ok||code!="739215"{t.Fatalf("valid code not found %q %v",code,ok)}
 if _,ok:=extractVerifiedCode("code 739215","unknown@other.example","test@operator.example",m,now);ok{
  t.Fatal("wrong sender allowed")
 }
 if _,ok:=extractVerifiedCode("code 739215","security@approved.example","other@operator.example",m,now);ok{
  t.Fatal("wrong recipient allowed")
 }
 if _,ok:=extractVerifiedCode("code 739215 and 739216","security@approved.example","test@operator.example",m,now);ok{
  t.Fatal("ambiguous OTP accepted")
 }
 old:=message("security@approved.example","test@operator.example","old",now.Add(-time.Hour))
 if _,ok:=extractVerifiedCode("code 739215","security@approved.example","test@operator.example",old,now);ok{
  t.Fatal("stale code accepted")
 }
}
func TestMailboxMustBeExplicitAndPublic(t *testing.T){
 good:=map[string]MailboxSettings{"owner":{Host:"imap.example.com",Sender:"security@approved.example"}}
 if _,err:=NewIMAPOTP(good,fakeMailSecrets{});err!=nil{t.Fatal(err)}
 for _,host:=range []string{"localhost","127.0.0.1","10.0.0.4","imap..example.com","imap.example.com:993"}{
  bad:=map[string]MailboxSettings{"owner":{Host:host,Sender:"security@approved.example"}}
  if _,err:=NewIMAPOTP(bad,fakeMailSecrets{});err==nil{t.Fatalf("accepted unsafe mailbox hostname %q",host)}
 }
 for _,ip:=range []string{"127.0.0.1","10.0.0.1","169.254.169.254","100.64.0.1","192.0.2.4","2001:db8::1","::1"}{
  if verifyMailIP(netip.MustParseAddr(ip)){t.Fatalf("mailbox special-use IP allowed %s",ip)}
 }
 if !verifyMailIP(netip.MustParseAddr("1.1.1.1")){t.Fatal("public mailbox IP rejected")}
}
