package bunnybrowserflow

import (
 "context"
 "errors"
 "os"

 "github.com/enowdev/antares/internal/browser"
 "github.com/enowdev/antares/internal/bunnyegress"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyquota"
)

// ApprovedChromiumFactory is constructed by trusted command/controller code,
// never by instructions fetched from a target. It uses a local restricted
// HTTPS CONNECT proxy plus the browser's CDP request-stage allowlist.
type ApprovedChromiumFactory struct {
 Executable string
 Headless bool
 VirtualPasskey bool
 ProxyURL string
 Scope ApprovedScope
}
func (f ApprovedChromiumFactory) New(ctx context.Context,actor,origin string)(Browser,error){
 approved:=false
 for _,v:=range f.Scope.AllowedOrigins{
  normalized,err:=strictOrigin(v)
  if err!=nil{return nil,errors.New("invalid approved browser scope")}
  if normalized==origin{approved=true}
 }
 if !approved{return nil,errors.New("external browser origin not approved")}
 s:=browser.New(browser.Options{
  Executable:f.Executable,Headless:f.Headless,Width:1050,Height:720,
  ExternalOrigins:f.Scope.AllowedOrigins,ExternalPostPaths:f.Scope.ApprovedPostPaths,
  ExternalMaxRequests:f.Scope.MaxBrowserRequests,ExternalMinIntervalMS:f.Scope.MinIntervalMS,
  ExternalProxyURL:f.ProxyURL,VirtualPasskey:f.VirtualPasskey,
 })
 if err:=s.Start(ctx);err!=nil{s.Stop();return nil,errors.New("scoped Chromium browser launch failed")}
 capture,err:=newCaptureVault(os.Getenv("BUNNY_BROWSER_CAPTURE_DIR"),f.Scope.EngagementID)
 if err!=nil{s.Stop();return nil,errors.New("configured encrypted screenshot vault unavailable")}
 return &chromeDriver{session:s,vault:capture},nil
}
// RunConfiguredApproved starts a DNS-pinning egress proxy and executes a
// trusted, prevalidated plan. The credentials remain in a trusted provider;
// no challenge completion is synthesized or bypassed.
func RunConfiguredApproved(ctx context.Context,scope ApprovedScope,plan Plan,
 provider Secrets,operator Handoff,manifest bunnyguard.Policy,headless bool)(Result,error){
 if _,err:=ValidateApprovedScope(scope,manifest);err!=nil{return Result{},err}
 // The shared cross-process budget is reserved before any browser egress.
 // Count all configured actors; the original per-browser CDP gate enforces
 // the per-identity maximum regardless of actual request count.
 actors:=map[string]bool{}
 for _,step:=range plan.Steps{actors[step.Actor]=true}
 if err:=actorBudget(plan,scope,manifest);err!=nil{return Result{},err}
 release,err:=bunnyquota.ExecutionLeaseShared(ctx,manifest.EngagementID)
 if err!=nil{return Result{},err}
 defer release()
 if _,err:=bunnyquota.ReserveShared(ctx,manifest.EngagementID,
  scope.MaxBrowserRequests*len(actors),manifest.MaxNetworkCalls);err!=nil{return Result{},err}
 proxy,err:=bunnyegress.New(bunnyegress.Config{
  Origins:scope.AllowedOrigins,MaxTunnels:scope.MaxTunnels,
 })
 if err!=nil{return Result{},err}
 address,err:=proxy.Start()
 if err!=nil{return Result{},err}
 defer proxy.Close()
 factory:=ApprovedChromiumFactory{
  Executable:os.Getenv("BUNNY_CHROME"),Headless:headless,
  ProxyURL:address,Scope:scope,
 }
 // Trust validation above is mandatory. The engine also validates every
 // step and the selected origin under the allowlist.
 origin,err:=strictOrigin(plan.Origin)
 if err!=nil{return Result{},err}
 allowed:=map[string]bool{}
 for _,s:=range scope.AllowedOrigins{
  o,err:=strictOrigin(s);if err!=nil{return Result{},err}
  allowed[o]=true
 }
 if !allowed[origin]{return Result{},errors.New("browser plan origin is not scope-approved")}
 if err:=validateSteps(plan);err!=nil{return Result{},err}
 if err:=actorBudget(plan,scope,manifest);err!=nil{return Result{},err}
 return runTrusted(ctx,plan,factory,provider,operator,origin,allowed)
}
