// bunny-python-proof generates and executes a Python HTTP evidence script for
// a preapproved scenario. Raw captures are encrypted with a local keyring key.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "time"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyscript"
)
func run()error{
 guardPath:=flag.String("guard","","BunnyGuard engagement JSON")
 planPath:=flag.String("plan","","Operator-approved Python scenario JSON")
 root:=flag.String("out","","Evidence vault directory")
 python:=flag.String("python","","Optional Python 3 executable")
 initKey:=flag.Bool("init-key",false,"Create a new evidence encryption key in OS credential store")
 exportRun:=flag.String("export-run","","Existing run ID to decrypt locally for authorized triage")
 confirm:=flag.Bool("confirm-sensitive",false,"Acknowledge decrypted evidence may contain cookies and private data")
 flag.Parse()
 if *initKey{
  if *guardPath!=""||*planPath!=""||*exportRun!=""{return errors.New("key initialization must be separate")}
  return bunnyartifact.InitKey()
 }
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return err}
 if *exportRun!=""{
  if !*confirm||*root==""||!bunnyscript.ValidRunID(*exportRun){
   return errors.New("sensitive export needs explicit --out, safe --export-run and --confirm-sensitive")
  }
  folder:=filepath.Join(*root,*exportRun)
  data,err:=bunnyartifact.Open(folder,"transcript","http_proof",key)
  if err!=nil{return err}
  output:=filepath.Join(folder,"TRIAGE-FULL-HTTP-PRIVATE.json")
  fd,err:=os.OpenFile(output,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
  if err!=nil{return err}
  if _,err:=fd.Write(data);err!=nil{fd.Close();os.Remove(output);return err}
  if err:=fd.Close();err!=nil{return err}
  fmt.Println("Sensitive evidence exported locally:",output)
  return nil
 }
 if *guardPath==""||*planPath==""||*root==""{
  return errors.New("--guard, --plan and --out are required")
 }
 guard,err:=bunnyguard.New(*guardPath)
 if err!=nil{return errors.New("invalid BunnyGuard authorization file")}
 raw,err:=os.ReadFile(*planPath)
 if err!=nil{return err}
 plan,err:=bunnyscript.ValidateJSON(raw,guard.Manifest())
 if err!=nil{return err}
 ctx,cancel:=context.WithTimeout(context.Background(),4*time.Minute)
 defer cancel()
 summary,err:=(bunnyscript.Runner{
  Root:*root,Python:*python,EncryptionKey:key,Secrets:bunnybrowserflow.KeyringSecrets{},
 }).Run(ctx,plan,guard.Manifest())
 if err!=nil{return fmt.Errorf("proof capture failed: %w",err)}
 output,err:=json.MarshalIndent(summary,"","  ")
 if err!=nil{return err}
 fmt.Println(string(output))
 return nil
}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
