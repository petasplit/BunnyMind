// bunny-approved-auth runs operator-authored, explicitly authorized external
// test-account browser steps. No network access or credentials are obtained
// from model-generated tool arguments.
package main

import (
 "bufio"
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
 "golang.org/x/term"
)
type operator struct{reader *bufio.Reader}
func (o operator) Authorize(_ context.Context,actor,kind string)error{
 fmt.Fprintf(os.Stderr,"Test persona %s requires %s. Complete the challenge in the browser. Type APPROVE to continue: ",actor,kind)
 answer,err:=o.reader.ReadString('\n')
 if err!=nil{return errors.New("operator handoff incomplete")}
 if strings.TrimSpace(answer)!="APPROVE"{return errors.New("operator did not approve the challenge")}
 return nil
}
func run()error{
 scopeFile:=flag.String("scope","","Operator-authored approved browser scope JSON")
 planFile:=flag.String("plan","","Operator-authored auth workflow JSON")
 guardFile:=flag.String("guard","","BunnyGuard engagement authorization JSON")
 secretRef:=flag.String("set-secret","","Store test-account secret in OS keyring as actor:key")
 headless:=flag.Bool("headless",false,"Run without a visible browser (only for flows without human challenges)")
 flag.Parse()
 if *secretRef!=""{
  actor,key,ok:=strings.Cut(*secretRef,":")
  if !ok||!bunnybrowserflow.ValidSecretRef(actor,key){return errors.New("invalid actor:key secret alias")}
  if !term.IsTerminal(int(os.Stdin.Fd())){return errors.New("secrets must be entered interactively in a local terminal")}
  fmt.Fprint(os.Stderr,"Enter the test-account secret (hidden): ")
  secret,err:=term.ReadPassword(int(os.Stdin.Fd()))
  fmt.Fprintln(os.Stderr)
  if err!=nil{return errors.New("could not read secret")}
  defer func(){for i:=range secret{secret[i]=0}}()
  if err:=bunnybrowserflow.SetApprovedSecret(actor,key,string(secret));err!=nil{return err}
  fmt.Fprintln(os.Stderr,"Stored secret reference in operating-system credential store.")
  return nil
 }
 if *scopeFile==""||*planFile==""||*guardFile==""{
  return errors.New("all of --scope, --plan and --guard are required")
 }
 scope,plan,err:=bunnybrowserflow.LoadApprovedConfiguration(*scopeFile,*planFile,*guardFile)
 if err!=nil{return fmt.Errorf("approved browser configuration rejected: %w",err)}
 guard,err:=bunnyguard.New(*guardFile)
 if err!=nil{return errors.New("invalid BunnyGuard manifest")}
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Minute)
 defer cancel()
 result,err:=bunnybrowserflow.RunConfiguredApproved(
  ctx,scope,plan,bunnybrowserflow.KeyringSecrets{},
  operator{reader:bufio.NewReader(os.Stdin)},guard.Manifest(),*headless,
 )
 if err!=nil{return fmt.Errorf("approved browser workflow failed: %w",err)}
 output,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return errors.New("could not serialize redacted result")}
 fmt.Println(string(output))
 return nil
}
func main(){
 if err:=run();err!=nil{
  fmt.Fprintln(os.Stderr,err)
  os.Exit(1)
 }
}
