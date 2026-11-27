package bunnybrowserflow

import (
 "strings"
 "testing"
 "time"

 "github.com/emersion/go-imap"
)
func testMagicMail(from,to string,when time.Time)*imap.Message{
 parts:=func(s string)*imap.Address{n:=strings.SplitN(s,"@",2);return &imap.Address{MailboxName:n[0],HostName:n[1]}}
 return &imap.Message{Envelope:&imap.Envelope{Date:when,From:[]*imap.Address{parts(from)},To:[]*imap.Address{parts(to)}}}
}
func TestMagicLinkUsesFreshOwnedMailboxAndExplicitEndpoint(t *testing.T){
 now:=time.Now().UTC()
 m:=testMagicMail("login@staging.example","owner@research.example",now)
 allowed:=map[string]bool{"https://staging.example":true}
 good:="Use https://staging.example/auth/magic/verify?token=one-time-private-value to sign in."
 link,err:=extractVerifiedMagicLink(good,"login@staging.example","owner@research.example",m,now,allowed,[]string{"/auth/magic"})
 if err!=nil||!strings.Contains(link,"one-time-private-value"){t.Fatalf("expected trusted magic link, got %q: %v",link,err)}
 for _,body:=range []string{
  "https://evil.example/auth/magic/verify?token=x",
  "https://staging.example/auth/magic-evil?token=x",
  "http://staging.example/auth/magic/verify?token=x",
  "https://staging.example:8443/auth/magic/verify?token=x",
  "https://staging.example/auth/%2e%2e/private?token=x",
  good+" https://staging.example/auth/magic/second?token=two",
 }{
  if _,err:=extractVerifiedMagicLink(body,"login@staging.example","owner@research.example",m,now,allowed,[]string{"/auth/magic"});err==nil{
   t.Fatalf("accepted unsafe or ambiguous link: %s",body)
  }
 }
}
func TestMagicLinkWrongSenderRecipientAndStaleMail(t *testing.T){
 now:=time.Now().UTC()
 good:="https://staging.example/auth/magic/confirm?code=secret"
 allow:=map[string]bool{"https://staging.example":true}
 message:=testMagicMail("login@staging.example","owner@research.example",now)
 cases:=[]struct{mail *imap.Message;sender,recipient string}{
  {message,"evil@example.com","owner@research.example"},
  {message,"login@staging.example","another@research.example"},
  {testMagicMail("login@staging.example","owner@research.example",now.Add(-time.Hour)),"login@staging.example","owner@research.example"},
 }
 for _,tc:=range cases {
  if _,err:=extractVerifiedMagicLink(good,tc.sender,tc.recipient,tc.mail,now,allow,[]string{"/auth/magic"});err==nil{
   t.Fatal("untrusted email link accepted")
  }
 }
}
