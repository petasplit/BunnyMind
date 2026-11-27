package bunnyauthflow

import (
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"
)
func TestOTPOneTimeAndExpired(t *testing.T){
 mailbox:=NewMailbox();svc:=NewService(mailbox,false)
 srv:=httptest.NewServer(svc.Handler());defer srv.Close()
 c:=srv.Client()
 email:="synthetic_user@example.test"
 post:=func(path,body string)(int,map[string]string){
  t.Helper()
  req,err:=http.NewRequest("POST",srv.URL+path,strings.NewReader(body));if err!=nil{t.Fatal(err)}
  resp,err:=c.Do(req);if err!=nil{t.Fatal(err)};defer resp.Body.Close()
  out:=map[string]string{};_ =json.NewDecoder(resp.Body).Decode(&out)
  return resp.StatusCode,out
 }
 if status,_:=post("/register",`{"email":"synthetic_user@example.test"}`);status!=202{t.Fatal("registration failed")}
 msg,ok:=mailbox.Last(email);if !ok{t.Fatal("verification email missing")}
 code,err:=ExtractCode(msg,email);if err!=nil{t.Fatal(err)}
 payload:=`{"email":"synthetic_user@example.test","code":"`+code+`"}`
 if codeStatus,_:=post("/session/verify",payload);codeStatus!=200{t.Fatal("valid OTP rejected")}
 if codeStatus,_:=post("/session/verify",payload);codeStatus!=401{t.Fatal("replayed OTP accepted")}
 if status,_:=post("/session/request",`{"email":"synthetic_user@example.test"}`);status!=202{t.Fatal("login request denied")}
 msg,_=mailbox.Last(email);code,_=ExtractCode(msg,email)
 svc.now=func()time.Time{return time.Now().Add(OTPExpiry+time.Second)}
 payload=`{"email":"synthetic_user@example.test","code":"`+code+`"}`
 if status,_:=post("/session/verify",payload);status!=401{t.Fatal("expired OTP was accepted")}
}
func TestOTPRetryBudget(t *testing.T){
 box:=NewMailbox();s:=NewService(box,false)
 server:=httptest.NewServer(s.Handler());defer server.Close()
 client:=server.Client()
 request:=func(path,body string)int{
  t.Helper()
  req,_:=http.NewRequest("POST",server.URL+path,strings.NewReader(body))
  res,err:=client.Do(req);if err!=nil{t.Fatal(err)};defer res.Body.Close()
  return res.StatusCode
 }
 email:="budget_user@example.test"
 if request("/register",`{"email":"budget_user@example.test"}`)!=202{t.Fatal("registration")}
 for i:=0;i<MaxAttempts;i++{
  if request("/session/verify",`{"email":"budget_user@example.test","code":"xxxxxx"}`)!=400{t.Fatal("non-numeric OTP should fail format validation")}
  if request("/session/verify",`{"email":"budget_user@example.test","code":"999999"}`)!=401{t.Fatal("wrong numeric OTP accepted")}
 }
 msg,_:=box.Last(email)
 code,_:=ExtractCode(msg,email)
 if request("/session/verify",`{"email":"budget_user@example.test","code":"`+code+`"}`)!=401{t.Fatal("retry limit not enforced")}
}
func TestNoExternalEmailAccepted(t *testing.T){
 s:=NewService(NewMailbox(),false);server:=httptest.NewServer(s.Handler());defer server.Close()
 request,_:=http.NewRequest("POST",server.URL+"/register",strings.NewReader(`{"email":"real@example.com"}`))
 res,err:=server.Client().Do(request);if err!=nil{t.Fatal(err)};defer res.Body.Close()
 if res.StatusCode!=400{t.Fatal("real email address allowed in synthetic-only lab")}
}
func TestExtractCodeSenderValidation(t *testing.T){
 msg:=Message{From:"attacker@example.test",To:"test_user@example.test",Body:"Your code: 123456"}
 if _,err:=ExtractCode(msg,msg.To);err==nil{t.Fatal("untrusted sender accepted")}
}
