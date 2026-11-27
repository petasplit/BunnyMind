package bunnyauthflow

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "net/url"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnyidentity"
 "github.com/enowdev/antares/internal/bunnychallenge"
)

const MaxCalls=28
type Outcome struct{
 Outcome string `json:"outcome"`
 AccountsCreated int `json:"accounts_created"`
 MailMessagesRead int `json:"mail_messages_read"`
 OTPCodesSubmitted int `json:"otp_codes_submitted"`
 OTPReplayDenied bool `json:"otp_replay_denied"`
 DistinctSessions bool `json:"distinct_sessions"`
 OwnerAccessObserved bool `json:"owner_access_observed"`
 ForeignAccessObserved bool `json:"foreign_access_observed"`
 AnonymousDenied bool `json:"anonymous_denied"`
 RotationInvalidatedOld bool `json:"rotation_invalidated_old"`
 LogoutInvalidated bool `json:"logout_invalidated"`
 RequestCount int `json:"request_count"`
 Notes string `json:"notes"`
}
type localClient struct{
 client *http.Client
 origin string
 calls int
}
func newLocalClient(origin string)(*localClient,error){
 u,err:=url.Parse(origin)
 if err!=nil||u.Scheme!="http"||u.User!=nil||u.RawQuery!=""||u.Fragment!=""||u.Path!="" {
  return nil,errors.New("synthetic workflow requires an HTTP numeric-loopback origin")
 }
 ip:=net.ParseIP(u.Hostname())
 if ip==nil||!ip.IsLoopback(){return nil,errors.New("only numeric loopback address permitted")}
 host,port:=u.Hostname(),u.Port()
 if port==""{return nil,errors.New("explicit local port required")}
 dialer:=&net.Dialer{Timeout:2*time.Second}
 transport:=&http.Transport{Proxy:nil,DisableKeepAlives:true,
  DialContext:func(ctx context.Context,network,address string)(net.Conn,error){
   dHost,dPort,e:=net.SplitHostPort(address)
   if e!=nil||net.ParseIP(dHost)==nil||!net.ParseIP(dHost).Equal(ip)||dPort!=port {
    return nil,errors.New("attempted to dial outside local test fixture")
   }
   return dialer.DialContext(ctx,"tcp",net.JoinHostPort(host,port))
  },
 }
 return &localClient{origin:origin,client:&http.Client{
  Transport:transport,Timeout:4*time.Second,
  CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
 }},nil
}
func (c *localClient) request(ctx context.Context,method,path,token string,payload any)(int,map[string]string,error){
 c.calls++
 if c.calls>MaxCalls{return 0,nil,errors.New("local request budget exhausted")}
 var body io.Reader
 if payload!=nil{
  data,err:=json.Marshal(payload);if err!=nil{return 0,nil,err}
  body=strings.NewReader(string(data))
 }
 req,err:=http.NewRequestWithContext(ctx,method,c.origin+path,body)
 if err!=nil{return 0,nil,err}
 if token!=""{req.Header.Set("Authorization","Bearer "+token)}
 if payload!=nil{req.Header.Set("Content-Type","application/json")}
 resp,err:=c.client.Do(req)
 if err!=nil{return 0,nil,errors.New("localhost fixture request failed")}
 defer resp.Body.Close()
 if resp.StatusCode>=300&&resp.StatusCode<400{return 0,nil,errors.New("local redirect refused")}
 data,err:=io.ReadAll(io.LimitReader(resp.Body,4097))
 if err!=nil||len(data)>4096{return 0,nil,errors.New("bounded local response read failed")}
 v:=map[string]string{}
 if err:=json.Unmarshal(data,&v);err!=nil{return 0,nil,errors.New("unexpected synthetic response")}
 return resp.StatusCode,v,nil
}
func mustStatus(status,want int,err error)error{
 if err!=nil{return err}
 if status!=want{return fmt.Errorf("unexpected local HTTP result (%d, expected %d)",status,want)}
 return nil
}
func (c *localClient) create(ctx context.Context,mail *Mailbox,email string)(token,resource string,err error){
 status,_,e:=c.request(ctx,"POST","/register","",mailRequest{Email:email})
 if e=mustStatus(status,202,e);e!=nil{return "","",e}
 msg,ok:=mail.Last(email)
 if !ok{return "","",errors.New("verification message missing from private sink")}
 otp,e:=ExtractCode(msg,email)
 if e!=nil{return "","",e}
 status,result,e:=c.request(ctx,"POST","/session/verify","",codeRequest{Email:email,Code:otp})
 if e=mustStatus(status,200,e);e!=nil{return "","",e}
 if len(result["token"])<32||len(result["resource_id"])<12{return "","",errors.New("fixture did not establish a session")}
 return result["token"],result["resource_id"],nil
}
func freshEmail() (string,error){
 rand,e:=secureHex(8);if e!=nil{return "",e}
 return "test_"+rand+"@example.test",nil
}
// Run creates two fresh synthetic users, reads an in-process test mailbox,
// enters OTPs, checks authenticated and anonymous resource access, rotates
// one session, requests another login OTP, tests OTP replay and logout.
// No externally configured URL, email provider or credentials are accepted.
func Run(ctx context.Context,deliberateExposure bool)(Outcome,error){
 box:=NewMailbox();svc:=NewService(box,deliberateExposure)
 server:=httptest.NewServer(svc.Handler())
 defer server.Close()
 client,err:=newLocalClient(server.URL);if err!=nil{return Outcome{},err}
 if tr,ok:=client.client.Transport.(*http.Transport);ok{defer tr.CloseIdleConnections()}
 alice,err:=freshEmail();if err!=nil{return Outcome{},err}
 bob,err:=freshEmail();if err!=nil{return Outcome{},err}
 // The coordinator reads OTP messages internally and stores bearer tokens
 // in a memory-only, role-scoped vault; no credential is returned by
 // enrollment and no test-account data is exposed to the agent tool.
 vault:=bunnyidentity.New()
 defer vault.Close()
 broker,err:=bunnychallenge.New(nil)
 if err!=nil{return Outcome{},err}
 coordinator:=Coordinator{Registration:LocalRegistrationPort{client},Inbox:box,Sessions:vault,Challenges:broker}
 a,err:=coordinator.Provision(ctx,"owner",alice);if err!=nil{return Outcome{},err}
 b,err:=coordinator.Provision(ctx,"foreign",bob);if err!=nil{return Outcome{},err}
 aliceResource,bobResource:=a.ResourceID,b.ResourceID
 if !a.ChallengeCompleted||!b.ChallengeCompleted||broker.Count()!=2{
  return Outcome{},errors.New("synthetic email verification tickets did not complete")
 }
 if aliceResource==bobResource{return Outcome{},errors.New("synthetic resources not isolated")}
 distinct:=false
 err=vault.Use("owner",func(ownerToken,_ string)error{
  return vault.Use("foreign",func(foreignToken,_ string)error{
   distinct=ownerToken!=foreignToken
   return nil
  })
 })
 if err!=nil||!distinct{return Outcome{},errors.New("synthetic sessions not isolated")}
 // Trusted callbacks are the only place raw session tokens are supplied
 // to the loopback HTTP transport. All tool results stay redacted.
 fromVault:=func(actor,method,path string,payload any)(int,map[string]string,error){
  var status int
  var body map[string]string
  err:=vault.Use(actor,func(token,_ string)error{
   var requestErr error
   status,body,requestErr=client.request(ctx,method,path,token,payload)
   return requestErr
  })
  return status,body,err
 }
 out:=Outcome{
  AccountsCreated:2,MailMessagesRead:2,OTPCodesSubmitted:2,
  DistinctSessions:true,Outcome:"inconclusive",
  Notes:"Synthetic localhost-only signup, trusted mailbox OTP extraction, bearer sessions, login, rotation and logout. No actual third-party account was created or accessed.",
 }
 st,owner,err:=fromVault("owner","GET","/resource/"+aliceResource,nil)
 if e:=mustStatus(st,200,err);e!=nil{return Outcome{},e}
 ownerMarker:=owner["marker"]
 if len(ownerMarker)<24{return Outcome{},errors.New("no synthetic owner marker")}
 out.OwnerAccessObserved=true
 st,foreign,err:=fromVault("foreign","GET","/resource/"+aliceResource,nil)
 if err!=nil{return Outcome{},err}
 out.ForeignAccessObserved=(st==200&&foreign["marker"]==ownerMarker)
 foreignDenied:=st==403||st==404
 st,_,err=client.request(ctx,"GET","/resource/"+aliceResource,"",nil)
 if e:=mustStatus(st,401,err);e!=nil{return Outcome{},e}
 out.AnonymousDenied=true
 st,me,err:=fromVault("foreign","GET","/me",nil)
 if e:=mustStatus(st,200,err);e!=nil{return Outcome{},e}
 if me["resource_id"]!=bobResource{return Outcome{},errors.New("foreign test identity mixed with owner")}
 st,rotation,err:=fromVault("owner","POST","/session/rotate",nil)
 if e:=mustStatus(st,200,err);e!=nil{return Outcome{},e}
 newAliceToken:=rotation["token"]
 if len(newAliceToken)<32{return Outcome{},errors.New("rotation did not issue a fresh token")}
 // Preserve one temporary token reference only to verify revocation;
 // never place it in any result or log.
 oldOwnerToken:=""
 err=vault.Use("owner",func(token,_ string)error{oldOwnerToken=token;return nil})
 if err!=nil{return Outcome{},err}
 if err:=vault.Rotate("owner",oldOwnerToken,newAliceToken,15*time.Minute);err!=nil{return Outcome{},err}
 st,_,err=client.request(ctx,"GET","/me",oldOwnerToken,nil)
 if e:=mustStatus(st,401,err);e!=nil{return Outcome{},e}
 st,_,err=fromVault("owner","GET","/me",nil)
 if e:=mustStatus(st,200,err);e!=nil{return Outcome{},e}
 out.RotationInvalidatedOld=true
 st,_,err=client.request(ctx,"POST","/session/request","",mailRequest{Email:alice})
 if e:=mustStatus(st,202,err);e!=nil{return Outcome{},e}
 msg,ok:=box.Last(alice)
 if !ok{return Outcome{},errors.New("login email not received")}
 code,err:=ExtractCode(msg,alice);if err!=nil{return Outcome{},err}
 out.MailMessagesRead++
 st,session,err:=client.request(ctx,"POST","/session/verify","",codeRequest{Email:alice,Code:code})
 if e:=mustStatus(st,200,err);e!=nil{return Outcome{},e}
 out.OTPCodesSubmitted++
 if session["token"]==""||session["token"]==newAliceToken{return Outcome{},errors.New("login failed to establish a separate session")}
 if err:=vault.Add("owner_login",session["token"],aliceResource,15*time.Minute);err!=nil{
  return Outcome{},errors.New("synthetic re-login session could not be isolated")
 }
 st,_,err=fromVault("owner_login","GET","/me",nil)
 if e:=mustStatus(st,200,err);e!=nil{return Outcome{},e}
 st,_,err=client.request(ctx,"POST","/session/verify","",codeRequest{Email:alice,Code:code})
 if e:=mustStatus(st,401,err);e!=nil{return Outcome{},e}
 out.OTPReplayDenied=true
 oldForeignToken:=""
 err=vault.Use("foreign",func(token,_ string)error{oldForeignToken=token;return nil})
 if err!=nil{return Outcome{},err}
 st,_,err=fromVault("foreign","POST","/session/logout",nil)
 if e:=mustStatus(st,200,err);e!=nil{return Outcome{},e}
 vault.Revoke("foreign")
 st,_,err=client.request(ctx,"GET","/me",oldForeignToken,nil)
 if e:=mustStatus(st,401,err);e!=nil{return Outcome{},e}
 if err:=vault.Use("foreign",func(_, _ string)error{return nil});err==nil{
  return Outcome{},errors.New("revoked synthetic persona remained available")
 }
 out.LogoutInvalidated=true
 if out.ForeignAccessObserved {out.Outcome="cross_user_access_observed_in_synthetic_lab"
 }else if foreignDenied {out.Outcome="cross_user_denied_in_synthetic_lab"
 }else{out.Outcome="inconclusive"}
 out.RequestCount=client.calls
 return out,nil
}
