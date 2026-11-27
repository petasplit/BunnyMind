// bunny-authflow-demo exercises synthetic email OTP and cross-user sessions
// against a disposable localhost fixture, never real web services.
package main

import (
 "context"
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "time"

 "github.com/enowdev/antares/internal/bunnyauthflow"
)
func main(){
 weak:=flag.Bool("weak",false,"simulate deliberately insecure cross-user permissions")
 flag.Parse()
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 outcome,err:=bunnyauthflow.Run(ctx,*weak)
 if err!=nil{fmt.Fprintln(os.Stderr,"local authentication demo failed:",err);os.Exit(1)}
 b,err:=json.MarshalIndent(outcome,"","  ")
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 fmt.Println(string(b))
 if outcome.AccountsCreated!=2||outcome.MailMessagesRead!=3||outcome.OTPCodesSubmitted!=3||
  !outcome.DistinctSessions||!outcome.OTPReplayDenied||
  !outcome.RotationInvalidatedOld||!outcome.LogoutInvalidated||!outcome.AnonymousDenied||
  !outcome.OwnerAccessObserved{
  fmt.Fprintln(os.Stderr,"synthetic authenticated-session acceptance checks failed")
  os.Exit(1)
 }
 want:="cross_user_denied_in_synthetic_lab"
 if *weak{want="cross_user_access_observed_in_synthetic_lab"}
 if outcome.Outcome!=want{
  fmt.Fprintln(os.Stderr,"synthetic cross-user access result unexpected")
  os.Exit(1)
 }
}
