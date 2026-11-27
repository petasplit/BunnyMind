package bunnybrowserflow

import (
 "context"
 "errors"
 "os"

 "github.com/enowdev/antares/internal/browser"
 "github.com/enowdev/antares/internal/bunnyegress"
 "github.com/enowdev/antares/internal/bunnyguard"
)

// ApprovedChromiumFactory is constructed by trusted command/controller code,
// never by instructions fetched from a target. It uses a local restricted
// HTTPS CONNECT proxy plus the browser's CDP request-stage allowlist.
type ApprovedChromiumFactory struct {
 Executable string
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
  Executable:f.Executable,Headless:true,Width:1050,Height:720,
  ExternalOrigins:f.Scope.AllowedOrigins,ExternalPostPaths:f.Scope.ApprovedPostPaths,
  ExternalMaxRequests:f.Scope.MaxBrowserRequests,ExternalMinIntervalMS:f.Scope.MinIntervalMS,
  ExternalProxyURL:f.ProxyURL,
 })
 if err:=s.Start(ctx);err!=nil{s.Stop();return nil,errors.New("scoped Chromium browser launch failed")}
 return &chromeDriver{session:s},nil
}
// RunConfiguredApproved starts a DNS-pinning egress proxy and executes a
// trusted, prevalidated plan. The credentials remain in a trusted provider;
// no challenge completion is synthesized or bypassed.
func RunConfiguredApproved(ctx context.Context,scope ApprovedScope,plan Plan,
 provider Secrets,operator Handoff,manifest bunnyguard.Policy)(Result,error){
 if _,err:=ValidateApprovedScope(scope,manifest);err!=nil{return Result{},err}
 proxy,err:=bunnyegress.New(bunnyegress.Config{
  Origins:scope.AllowedOrigins,MaxTunnels:scope.MaxTunnels,
 })
 if err!=nil{return Result{},err}
 address,err:=proxy.Start()
 if err!=nil{return Result{},err}
 defer proxy.Close()
 factory:=ApprovedChromiumFactory{
  Executable:os.Getenv("BUNNY_CHROME"),
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
 return runTrusted(ctx,plan,factory,provider,operator,origin,allowed)
}
