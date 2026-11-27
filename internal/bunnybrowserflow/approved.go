package bunnybrowserflow

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "io"
 "net/url"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
)

type ApprovedScope struct {
 EngagementID string `json:"engagement_id"`
 AllowedOrigins []string `json:"allowed_origins"`
 ApprovedPostPaths []string `json:"approved_post_paths"`
 MaxBrowserRequests int `json:"max_browser_requests"`
 MaxTunnels int `json:"max_tunnels"`
 MinIntervalMS int `json:"min_interval_ms"`
}
func strictOrigin(s string)(string,error){
 u,err:=url.Parse(s)
 if err!=nil||u==nil||u.Scheme!="https"||u.Hostname()==""||
  u.User!=nil||u.Opaque!=""||u.Fragment!=""||u.RawQuery!=""||
  (u.Path!=""&&u.Path!="/")||(u.Port()!=""&&u.Port()!="443")||
  strings.HasSuffix(u.Hostname(),".")||strings.Contains(u.Hostname(),"%"){
   return "",errors.New("approved browser requires an HTTPS origin on port 443")
 }
 return "https://"+strings.ToLower(u.Hostname()),nil
}
func approvedBrowserURL(raw string,approved map[string]bool)bool{
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.Scheme!="https"||u.Hostname()==""||
  u.User!=nil||u.Opaque!=""||(u.Port()!=""&&u.Port()!="443"){return false}
 return approved["https://"+strings.ToLower(u.Hostname())]
}
func validatePostPath(p string)bool{
 if len(p)<1||len(p)>256||!strings.HasPrefix(p,"/")||strings.HasPrefix(p,"//")||
  strings.ContainsAny(p,"?#\\\r\n")||strings.Contains(p,"%")||strings.Contains(p,".."){return false}
 return true
}
// ValidateApprovedScope ties the trusted external configuration to the
// separately loaded BunnyGuard permission manifest. No subdomain wildcards,
// scheme upgrades or inferred origins are authorized.
func ValidateApprovedScope(scope ApprovedScope,manifest bunnyguard.Policy)(map[string]bool,error){
 if scope.EngagementID==""||scope.EngagementID!=manifest.EngagementID{
  return nil,errors.New("approved browser scope does not match current engagement")
 }
 if len(scope.AllowedOrigins)==0||len(scope.AllowedOrigins)>32||
  len(scope.ApprovedPostPaths)>64||scope.MaxBrowserRequests<1||
  scope.MaxBrowserRequests>1000||scope.MaxBrowserRequests>manifest.MaxNetworkCalls||
  scope.MaxTunnels<1||scope.MaxTunnels>64||
  scope.MinIntervalMS<0||scope.MinIntervalMS>5000||
  scope.MinIntervalMS<manifest.MinIntervalMS{
  return nil,errors.New("external browser scope exceeds engagement limits")
 }
 manifestOrigins:=map[string]bool{}
 for _,raw:=range manifest.AllowedOrigins{
  origin,err:=strictOrigin(raw);if err!=nil{continue}
  manifestOrigins[origin]=true
 }
 approved:=map[string]bool{}
 for _,raw:=range scope.AllowedOrigins {
  origin,err:=strictOrigin(raw)
  if err!=nil||!manifestOrigins[origin]{return nil,errors.New("origin not explicitly authorized by BunnyGuard")}
  approved[origin]=true
 }
 postAllowed:=false
 for _,method:=range manifest.AllowedMethods{if strings.EqualFold(method,"POST"){postAllowed=true}}
 if len(scope.ApprovedPostPaths)>0&&!postAllowed{
  return nil,errors.New("POST workflows require POST permission in BunnyGuard manifest")
 }
 for _,p:=range scope.ApprovedPostPaths{
  if !validatePostPath(p){return nil,errors.New("invalid approved POST endpoint")}
 }
 return approved,nil
}
func loadJSON(path string,v any)error{
 f,err:=os.Open(path);if err!=nil{return err}
 defer f.Close()
 contents,err:=io.ReadAll(io.LimitReader(f,64*1024+1))
 if err!=nil||len(contents)>64*1024{return errors.New("trusted configuration must be <=64 KiB")}
 dec:=json.NewDecoder(bytes.NewReader(contents))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(v);err!=nil{return err}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return errors.New("configuration must contain one JSON object")}
 return nil
}
// LoadApprovedScope validates an operator-owned external-target policy without
// requiring a fixed workflow; adaptive mode may discover form structures.
func LoadApprovedScope(scopePath,guardPath string)(ApprovedScope,error){
 if strings.TrimSpace(guardPath)==""{return ApprovedScope{},errors.New("BunnyGuard policy required")}
 guard,err:=bunnyguard.New(guardPath)
 if err!=nil{return ApprovedScope{},errors.New("BunnyGuard policy invalid")}
 var scope ApprovedScope
 if err:=loadJSON(scopePath,&scope);err!=nil{return ApprovedScope{},err}
 if _,err:=ValidateApprovedScope(scope,guard.Manifest());err!=nil{return ApprovedScope{},err}
 return scope,nil
}
// LoadApprovedConfiguration loads a trusted local scope and JSON workflow;
// no model-provided URL or secret is accepted.
func LoadApprovedConfiguration(scopePath,planPath,guardPath string)(ApprovedScope,Plan,error){
 if strings.TrimSpace(guardPath)==""{return ApprovedScope{},Plan{},errors.New("BunnyGuard manifest required")}
 g,err:=bunnyguard.New(guardPath)
 if err!=nil{return ApprovedScope{},Plan{},errors.New("invalid BunnyGuard engagement policy")}
 var scope ApprovedScope
 if err:=loadJSON(scopePath,&scope);err!=nil{return ApprovedScope{},Plan{},err}
 allow,err:=ValidateApprovedScope(scope,g.Manifest());if err!=nil{return ApprovedScope{},Plan{},err}
 var plan Plan
 if err:=loadJSON(planPath,&plan);err!=nil{return ApprovedScope{},Plan{},err}
 origin,err:=strictOrigin(plan.Origin)
 if err!=nil||!allow[origin]{return ApprovedScope{},Plan{},errors.New("plan origin not authorized")}
 if err:=validateSteps(plan);err!=nil{return ApprovedScope{},Plan{},err}
 if err:=actorBudget(plan,scope,g.Manifest());err!=nil{return ApprovedScope{},Plan{},err}
 return scope,plan,nil
}
// RunApproved reuses the bounded workflow executor but accepts explicitly
// approved external HTTPS origins. The injected factory must itself enforce
// a DNS-pinned proxy and a request-stage browser gate.

func actorBudget(plan Plan,scope ApprovedScope,manifest bunnyguard.Policy)error{
 actors:=map[string]bool{}
 for _,step:=range plan.Steps{actors[step.Actor]=true}
 if len(actors)==0||scope.MaxBrowserRequests*len(actors)>manifest.MaxNetworkCalls{
  return errors.New("aggregate browser identity budget exceeds engagement request budget")
 }
 return nil
}
func RunApproved(ctx context.Context,p Plan,scope ApprovedScope,factory Factory,secrets Secrets,handoff Handoff,manifest bunnyguard.Policy)(Result,error){
 allow,err:=ValidateApprovedScope(scope,manifest)
 if err!=nil{return Result{},err}
 origin,err:=strictOrigin(p.Origin)
 if err!=nil||!allow[origin]{return Result{},errors.New("workflow origin is not approved")}
 if err:=validateSteps(p);err!=nil{return Result{},err}
 if err:=actorBudget(p,scope,manifest);err!=nil{return Result{},err}
 return runTrusted(ctx,p,factory,secrets,handoff,origin,allow)
}
