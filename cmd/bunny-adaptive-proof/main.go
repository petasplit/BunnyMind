// bunny-adaptive-proof builds and executes changing Python test scenarios
// using approved owned endpoint inventories and negative controls.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "time"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnyautoprobe"
 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyscript"
)
func run()error{
 guardFile:=flag.String("guard","","Trusted BunnyGuard engagement manifest")
 specFile:=flag.String("spec","","Operator-owned endpoint inventory and adaptive study policy")
 root:=flag.String("out","","Local private evidence output directory")
 py:=flag.String("python","","Optional Python 3 interpreter")
 flag.Parse()
 if *guardFile==""||*specFile==""||*root==""{
  return errors.New("--guard, --spec and --out are mandatory")
 }
 policy,err:=bunnyguard.New(*guardFile)
 if err!=nil{return errors.New("invalid BunnyGuard engagement manifest")}
 raw,err:=os.ReadFile(*specFile)
 if err!=nil{return errors.New("cannot read operator-approved adaptive specification")}
 spec,err:=bunnyautoprobe.Load(raw,policy.Manifest())
 if err!=nil{return fmt.Errorf("adaptive study rejected: %w",err)}
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return err}
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Minute)
 defer cancel()
 result,err:=(bunnyautoprobe.Runner{
  Proof:bunnyscript.Runner{Root:*root,Python:*py,EncryptionKey:key,
   Secrets:bunnybrowserflow.KeyringSecrets{}},
 }).Execute(ctx,spec,policy.Manifest())
 if err!=nil{return fmt.Errorf("adaptive Python evidence capture failed: %w",err)}
 payload,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return err}
 fmt.Println(string(payload))
 return nil
}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
