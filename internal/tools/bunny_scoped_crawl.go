package tools

import (
 "context"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnycrawl"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/config"
)

type scopedCrawlTool struct{}
func (scopedCrawlTool) Name()string{return "scoped_crawl"}
func (scopedCrawlTool) Description()string {
 return "Crawl a small number of approved same-origin HTML pages using GET only "+
  "with DNS-pinned egress, no redirects or cookies, a 64 KiB body cap, "+
  "a minimum 250ms interval, dangerous-link filtering, and a shared evidence "+
  "request ledger. Requires an operator-supplied BunnyGuard manifest. "+
  "It does not submit forms, touch other origins, or prove vulnerabilities."
}
func (scopedCrawlTool) RequiresApproval()bool{return false}
func (scopedCrawlTool) UntrustedOutput()bool{return true}
func (scopedCrawlTool) Schema()map[string]any {
 return schema(map[string]any{
  "url":prop("string","Exact starting URL within an approved BunnyGuard origin."),
  "max_pages":propDefault("integer","Page limit, 1..16 (default 8).",8),
  "max_depth":propDefault("integer","Link depth 0..3 (default 1).",1),
 },"url")
}
func (scopedCrawlTool) Execute(ctx context.Context,in Input)Result{
 var args struct {
  URL string `json:"url"`
  MaxPages int `json:"max_pages"`
  MaxDepth int `json:"max_depth"`
 }
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid crawl spec: %v",err)}
 if args.MaxPages==0{args.MaxPages=8}
 if args.MaxDepth==0{args.MaxDepth=1}
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if policyPath==""{return Errorf("active crawler requires an operator-owned BunnyGuard manifest")}
 guard,err:=bunnyguard.New(policyPath)
 if err!=nil{return Errorf("cannot load reviewed crawl authorization: %v",err)}
 p:=guard.Manifest()
 study:=bunnycrawl.Plan{EngagementID:p.EngagementID,SeedURL:args.URL,
  MaxPages:args.MaxPages,MaxDepth:args.MaxDepth}
 if err:=bunnycrawl.Validate(study,p);err!=nil{return Errorf("crawl blocked by scope: %v",err)}
 root:=strings.TrimSpace(os.Getenv("BUNNY_PROOF_OUTPUT"))
 if root==""{root=config.Path("bunnymind","evidence")}
 if in.Emit!=nil{in.Emit(Progress{Tool:"scoped_crawl",Message:"Crawling permitted pages with capped GET requests"})}
 summary,err:=bunnycrawl.Run(ctx,study,p,root)
 if err!=nil{return Errorf("approved crawl failed: %v",err)}
 raw,err:=json.MarshalIndent(summary,"","  ")
 if err!=nil{return Errorf("crawl report encoding error")}
 if in.Emit!=nil{in.Emit(Progress{Tool:"scoped_crawl",Message:"Completed bounded crawl; recorded endpoint inventory"})}
 return Text(string(raw))
}
