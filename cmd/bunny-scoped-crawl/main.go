// Command bunny-scoped-crawl performs an explicitly approved GET-only
// same-origin crawl and saves a private endpoint inventory. No exploitation.
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

 "github.com/enowdev/antares/internal/bunnycrawl"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/config"
)

func run()error{
 guardPath:=flag.String("guard","","Operator-reviewed BunnyGuard JSON")
 seed:=flag.String("url","","Exact approved origin or starting URL")
 maxPages:=flag.Int("max-pages",8,"Maximum GET page requests (1..16)")
 depth:=flag.Int("depth",1,"Maximum HTML link depth (0..3)")
 out:=flag.String("out","","Private evidence directory (defaults to BunnyMind evidence home)")
 flag.Parse()
 if *guardPath==""||*seed==""||flag.NArg()>0{
  return errors.New("usage: bunny-scoped-crawl --guard guard.json --url https://approved.example --max-pages 8 --depth 1")
 }
 g,err:=bunnyguard.New(*guardPath)
 if err!=nil{return fmt.Errorf("invalid operator-owned manifest: %w",err)}
 p:=g.Manifest()
 plan:=bunnycrawl.Plan{EngagementID:p.EngagementID,SeedURL:*seed,MaxPages:*maxPages,MaxDepth:*depth}
 if err:=bunnycrawl.Validate(plan,p);err!=nil{return err}
 root:=strings.TrimSpace(*out)
 if root==""{root=config.Path("bunnymind","evidence")}
 ctx,cancel:=context.WithTimeout(context.Background(),4*time.Minute)
 defer cancel()
 summary,err:=bunnycrawl.Run(ctx,plan,p,root)
 if err!=nil{return err}
 raw,err:=json.MarshalIndent(summary,"","  ")
 if err!=nil{return err}
 fmt.Println(string(raw))
 return nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
