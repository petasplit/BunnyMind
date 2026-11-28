package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "time"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
)

func run() error {
 guard:=flag.String("guard","","Reviewed BunnyGuard manifest")
 scope:=flag.String("scope","","Approved browser scope")
 login:=flag.String("login","","Trusted operator-authored login")
 crawl:=flag.String("crawl","","Read-only crawl plan")
 output:=flag.String("out","","Private evidence directory")
 flag.Parse()
 if *guard==""||*scope==""||*login==""||*crawl==""||*output==""||flag.NArg()!=0{
  return errors.New("usage: BunnyMind-browser-replay.exe --guard guard.json --scope browser.json --login login.json --crawl crawl.json --out Evidence")
 }
 s,p,c,manifest,err:=bunnybrowserflow.LoadHeadlessConfiguration(*guard,*scope,*login,*crawl)
 if err!=nil{return fmt.Errorf("replay authorization invalid: %w",err)}
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Minute)
 defer cancel()
 out,err:=bunnybrowserflow.ReplayApprovedFreshState(ctx,s,p,c,manifest,*output)
 if err!=nil{return err}
 raw,err:=json.MarshalIndent(out,"","  ")
 if err!=nil{return err}
 fmt.Println(string(raw))
 return nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
