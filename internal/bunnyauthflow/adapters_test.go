package bunnyauthflow

import (
 "context"
 "encoding/json"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyidentity"
 "github.com/enowdev/antares/internal/bunnychallenge"
)
func TestTrustedPortsRegisterOTPAndVault(t *testing.T){
 box:=NewMailbox();svc:=NewService(box,false)
 server:=httptest.NewServer(svc.Handler());defer server.Close()
 client,err:=newLocalClient(server.URL);if err!=nil{t.Fatal(err)}
 vault:=bunnyidentity.New();defer vault.Close()
 broker,err:=bunnychallenge.New(nil);if err!=nil{t.Fatal(err)}
 flow:=Coordinator{Registration:LocalRegistrationPort{client},Inbox:box,Sessions:vault,Challenges:broker}
 created,err:=flow.Provision(context.Background(),"owner","user_123@example.test")
 if err!=nil{t.Fatal(err)}
 if created.Actor!="owner"||len(created.ResourceID)<12||!created.CodeConsumed||!created.SessionVaulted||!created.ChallengeCompleted{t.Fatalf("%+v",created)}
 if err:=vault.Use("owner",func(token,resource string)error{
  if resource!=created.ResourceID||len(token)<32{t.Fatal("missing synthetic session credentials")}
  return nil
 });err!=nil{t.Fatal(err)}
 b,_:=json.Marshal(created)
 if strings.Contains(string(b),"user_123@example.test")||strings.Contains(string(b),"Bearer "){t.Fatal("secret account identity appeared in output")}
}
func TestPortsRejectExternalMailboxAddress(t *testing.T){
 box:=NewMailbox();svc:=NewService(box,false)
 server:=httptest.NewServer(svc.Handler());defer server.Close()
 client,_:=newLocalClient(server.URL)
 vault:=bunnyidentity.New();defer vault.Close()
 flow:=Coordinator{Registration:LocalRegistrationPort{client},Inbox:box,Sessions:vault}
 if _,err:=flow.Provision(context.Background(),"owner","real@anotherdomain.com");err==nil{t.Fatal("real address accepted")}
 if client.calls!=0{t.Fatal("network requests occurred before input validation")}
}
func TestPortsRejectUntrustedSender(t *testing.T){
 box:=NewMailbox();svc:=NewService(box,false)
 server:=httptest.NewServer(svc.Handler());defer server.Close()
 client,_:=newLocalClient(server.URL)
 vault:=bunnyidentity.New();defer vault.Close()
 fake:=badInbox{}
 flow:=Coordinator{Registration:LocalRegistrationPort{client},Inbox:fake,Sessions:vault}
 if _,err:=flow.Provision(context.Background(),"owner","user_123@example.test");err==nil{t.Fatal("untrusted sender should fail")}
 if vault.Count()!=0{t.Fatal("session stored for unverified email")}
}
type badInbox struct{}
func (badInbox) Latest(_ context.Context,email string)(Message,error){
 return Message{From:"untrusted@other.test",To:email,Body:"Code 123456"},nil
}
func TestDuplicateActorNoAccountOverwrite(t *testing.T){
 box:=NewMailbox();svc:=NewService(box,false)
 server:=httptest.NewServer(svc.Handler());defer server.Close()
 client,_:=newLocalClient(server.URL)
 vault:=bunnyidentity.New();defer vault.Close()
 flow:=Coordinator{Registration:LocalRegistrationPort{client},Inbox:box,Sessions:vault}
 if _,err:=flow.Provision(context.Background(),"owner","test_01@example.test");err!=nil{t.Fatal(err)}
 if _,err:=flow.Provision(context.Background(),"owner","test_02@example.test");err==nil{t.Fatal("identity overwrite allowed")}
 if vault.Count()!=1{t.Fatal("identity altered after duplicate actor")}
}
