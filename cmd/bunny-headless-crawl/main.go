// bunny-headless-crawl runs an operator-authored test-account login and
// then read-only Chromium endpoint discovery. Never accepts target/model
// instructions as a substitute for reviewed local JSON authorization.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/config"
)

func run()error{
 guard:=flag.String("guard","","Reviewed BunnyGuard manifest")
 scope:=flag.String("scope","","Reviewed browser HTTPS origin/method policy")
 login:=flag.String("login","","Trusted test-account login workflow")
 crawl:=flag.String("crawl","","Bounded authenticated crawl configuration")
 out:=flag.String("out","","Private encrypted evidence root")
 flag.Parse()
 if *guard==""||*scope==""||*login==""||*crawl==""||flag.NArg()!=0{
  return errors.New("usage: bunny-headless-crawl --guard guard.json --scope approved-browser.json --login trusted-login.json --crawl headless-crawl.json --out Evidence")
 }
 p,flow,cfg,manifest,err:=bunnybrowserflow.LoadHeadlessConfiguration(*guard,*scope,*login,*crawl)
 if err!=nil{return fmt.Errorf("headless configuration not approved: %w",err)}
 root:=strings.TrimSpace(*out)
 if root==""{root=config.Path("bunnymind","evidence")}
 ctx,cancel:=context.WithTimeout(context.Background(),7*time.Minute)
 defer cancel()
 report,err:=bunnybrowserflow.RunConfiguredHeadlessCrawl(ctx,p,flow,cfg,manifest,root)
 if err!=nil{return fmt.Errorf("approved headless crawl failed: %w",err)}
 raw,err:=json.MarshalIndent(report,"","  ")
 if err!=nil{return err}
 fmt.Println(string(raw))
 return nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
