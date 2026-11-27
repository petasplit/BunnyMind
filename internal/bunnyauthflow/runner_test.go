package bunnyauthflow

import (
 "context"
 "encoding/json"
 "strings"
 "testing"
 "time"
)
func TestSafeAutonomousSignupOTPAndSessions(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 r,err:=Run(ctx,false)
 if err!=nil{t.Fatal(err)}
 if r.Outcome!="cross_user_denied_in_synthetic_lab"||r.AccountsCreated!=2||
 r.MailMessagesRead!=3||r.OTPCodesSubmitted!=3||r.EmailChallengeTicketsCompleted!=2||
 !r.OTPReplayDenied||!r.DistinctSessions||!r.OwnerAccessObserved||
 !r.AnonymousDenied||r.ForeignAccessObserved||!r.RotationInvalidatedOld||
 !r.LogoutInvalidated||r.RequestCount>MaxCalls{t.Fatalf("unexpected workflow %+v",r)}
}
func TestDeliberatelyWeakLocalAuthorizationDetected(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
 defer cancel()
 out,err:=Run(ctx,true)
 if err!=nil{t.Fatal(err)}
 if out.Outcome!="cross_user_access_observed_in_synthetic_lab"||
 !out.ForeignAccessObserved||!out.AnonymousDenied{t.Fatalf("%+v",out)}
}
func TestOutputsNeverContainOTPsTokensOrMail(t *testing.T){
 out,err:=Run(context.Background(),false);if err!=nil{t.Fatal(err)}
 b,_:=json.Marshal(out)
 for _,secret:=range []string{Sender,"@example.test","Bearer ","verification code","token","marker"}{
  if strings.Contains(string(b),secret){t.Fatalf("unwanted email/secret material in result: %s",secret)}
 }
}
func TestOnlyNumericLoopbackClientAllowed(t *testing.T){
 for _,dest:=range []string{"http://example.com:8080","https://127.0.0.1:4444","http://localhost:8080","http://169.254.169.254:80","http://10.0.0.1:9999"}{
  if _,err:=newLocalClient(dest);err==nil{t.Fatalf("client permitted external destination %s",dest)}
 }
}
