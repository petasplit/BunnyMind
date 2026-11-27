package tools

import (
 "context"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnynet"
)

// scopedReadTool makes bounded GET/HEAD requests only under a validated
// engagement policy, with DNS/address checks and no redirect following.
type scopedReadTool struct{}
func (scopedReadTool) Name()string{return "scoped_read"}
func (scopedReadTool) Description()string{
 return "Read one authorized HTTP(S) URL with a fresh direct connection, "+
 "verified destination IP, no redirect following, no proxy, no cookies, and a 64 KiB response cap. "+
 "Requires ANTARES_BUNNY_GUARD_POLICY; only GET and HEAD are supported. "+
 "The response preview is optional and may contain sensitive/untrusted page data."
}
// A validated, preauthorized engagement manifest grants the read-only
// GET/HEAD capability. Explicit approval remains required for any tool
// with additional effects; this transport enforces origin/IP/redirect caps.
func (scopedReadTool) RequiresApproval()bool{return false}
func (scopedReadTool) UntrustedOutput()bool{return true}
func (scopedReadTool) Schema()map[string]any{
 return schema(map[string]any{
  "url":prop("string","Absolute URL inside the exact declared origin."),
  "method":propEnum("Read-only HTTP method.","GET","HEAD"),
  "preview_bytes":propDefault("integer","Optional response body preview, 0..8192 bytes. Use 0 for hash/metadata only.",0),
 },"url")
}
func (scopedReadTool) Execute(ctx context.Context,in Input) Result {
 var args struct{
  URL string `json:"url"`
  Method string `json:"method"`
  PreviewBytes int `json:"preview_bytes"`
 }
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid arguments: %v",err)}
 path:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if path==""{return Errorf("scoped_read requires ANTARES_BUNNY_GUARD_POLICY manifest")}
 g,err:=bunnyguard.New(path)
 if err!=nil{return Errorf("invalid engagement policy: %v",err)}
 p:=g.Manifest()
 reader,err:=bunnynet.New(bunnynet.Policy{Origins:p.AllowedOrigins,PrivateCIDRs:p.AllowedCIDRs})
 if err!=nil{return Errorf("invalid network policy: %v",err)}
 result,err:=reader.Read(ctx,args.URL,args.Method,args.PreviewBytes)
 if err!=nil{return Errorf("scoped read blocked or failed: %v",err)}
 payload,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return Errorf("cannot encode scoped read: %v",err)}
 return Text(string(payload))
}
