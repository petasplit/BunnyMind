package bunnybrowserflow

import (
 "context"
 "errors"
 "os"

 "github.com/enowdev/antares/internal/bunnyegress"
 "github.com/enowdev/antares/internal/bunnyguard"
)
type AdaptiveBatchConfig struct {
 Actors []string `json:"actors"`
 Mode string `json:"mode"`
 EntryPath string `json:"entry_path"`
}
type AdaptiveBatchResult struct {
 Outcomes []AdaptiveResult `json:"outcomes"`
 TotalActors int `json:"total_actors"`
 Disclaimer string `json:"disclaimer"`
}
func ValidateAdaptiveBatch(c AdaptiveBatchConfig,scope ApprovedScope,manifest bunnyguard.Policy)error{
 if len(c.Actors)==0||len(c.Actors)>MaxActors{
  return errors.New("adaptive batch needs 1..4 test identities")
 }
 seen:=map[string]bool{}
 for _,actor:=range c.Actors{
  if seen[actor]{return errors.New("duplicate test identity")}
  seen[actor]=true
  if err:=validateAdaptive(AdaptiveConfig{Actor:actor,Mode:c.Mode,EntryPath:c.EntryPath});err!=nil{return err}
 }
 if scope.MaxBrowserRequests*len(c.Actors)>manifest.MaxNetworkCalls{
  return errors.New("aggregate adaptive browser budget exceeds BunnyGuard")
 }
 return nil
}
func LoadAdaptiveBatch(path string)(AdaptiveBatchConfig,error){
 var c AdaptiveBatchConfig
 if err:=loadJSON(path,&c);err!=nil{return c,err}
 if len(c.Actors)==0{return c,errors.New("adaptive test identities required")}
 for _,actor:=range c.Actors{
  if err:=validateAdaptive(AdaptiveConfig{Actor:actor,Mode:c.Mode,EntryPath:c.EntryPath});err!=nil{return c,err}
 }
 return c,nil
}
func LoadMailboxConfiguration(path string)(MailboxConfig,error){
 var c MailboxConfig
 if err:=loadJSON(path,&c);err!=nil{return c,err}
 return c,validateMailboxConfig(c)
}
// RunConfiguredAdaptive shares an operator-approved public HTTPS proxy across
// disposable, isolated browser profiles. It does not autonomously enumerate
// sites or modify paths outside the approved application.
func RunConfiguredAdaptive(ctx context.Context,scope ApprovedScope,c AdaptiveBatchConfig,
 provider Secrets,operator Handoff,manifest bunnyguard.Policy,headless bool)(AdaptiveBatchResult,error){
 if _,err:=ValidateApprovedScope(scope,manifest);err!=nil{return AdaptiveBatchResult{},err}
 if err:=ValidateAdaptiveBatch(c,scope,manifest);err!=nil{return AdaptiveBatchResult{},err}
 if provider==nil{return AdaptiveBatchResult{},errors.New("trusted account/OTP provider required")}
 if len(scope.ApprovedPostPaths)==0{return AdaptiveBatchResult{},errors.New("explicit POST endpoint allowlist required")}
 proxy,err:=bunnyegress.New(bunnyegress.Config{Origins:scope.AllowedOrigins,MaxTunnels:scope.MaxTunnels})
 if err!=nil{return AdaptiveBatchResult{},err}
 address,err:=proxy.Start()
 if err!=nil{return AdaptiveBatchResult{},err}
 defer proxy.Close()
 factory:=ApprovedChromiumFactory{Executable:os.Getenv("BUNNY_CHROME"),
  Headless:headless,ProxyURL:address,Scope:scope}
 result:=AdaptiveBatchResult{Outcomes:[]AdaptiveResult{},TotalActors:len(c.Actors),
  Disclaimer:"Only operator-approved account operations were performed. Auth state indicators require independent verification; this is not an exploitation result."}
 for _,actor:=range c.Actors{
  out,err:=RunAdaptiveApproved(ctx,AdaptiveConfig{Actor:actor,Mode:c.Mode,EntryPath:c.EntryPath},
   scope,factory,provider,operator,manifest)
  if err!=nil{return result,err}
  result.Outcomes=append(result.Outcomes,out)
 }
 return result,nil
}
