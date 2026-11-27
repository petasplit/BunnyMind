package bunnybrowserflow

import (
 "context"
 "errors"
 "os"

 "github.com/enowdev/antares/internal/bunnyegress"
 "github.com/enowdev/antares/internal/bunnyguard"
)

// LoadAdaptiveConfiguration verifies all three operator-owned files before
// any network session exists. A URL or path supplied by a model is never
// accepted by the adaptive agent entry point.
func LoadAdaptiveConfiguration(scopeFile,adaptiveFile,guardFile string)(ApprovedScope,AdaptiveConfig,error){
 if guardFile==""{return ApprovedScope{},AdaptiveConfig{},errors.New("explicit BunnyGuard policy required")}
 guard,err:=bunnyguard.New(guardFile)
 if err!=nil{return ApprovedScope{},AdaptiveConfig{},errors.New("invalid BunnyGuard policy")}
 var scope ApprovedScope
 if err:=loadJSON(scopeFile,&scope);err!=nil{return ApprovedScope{},AdaptiveConfig{},err}
 var cfg AdaptiveConfig
 if err:=loadJSON(adaptiveFile,&cfg);err!=nil{return ApprovedScope{},AdaptiveConfig{},err}
 if err:=ValidateAdaptive(cfg,scope,guard.Manifest());err!=nil{return ApprovedScope{},AdaptiveConfig{},err}
 return scope,cfg,nil
}

// RunConfiguredAdaptive performs real approved HTTPS browsing under the same
// proxy and CDP origin checks as the predefined v0.24 workflows. It only
// changes how allowed authentication steps are selected from the page.
func RunConfiguredAdaptive(ctx context.Context,scope ApprovedScope,cfg AdaptiveConfig,
 secrets Secrets,operator Handoff,manifest bunnyguard.Policy,headless bool)(Result,error){
 if err:=ValidateAdaptive(cfg,scope,manifest);err!=nil{return Result{},err}
 if secrets==nil{return Result{},errors.New("trusted test-account credentials missing")}
 egress,err:=bunnyegress.New(bunnyegress.Config{
  Origins:scope.AllowedOrigins,MaxTunnels:scope.MaxTunnels,
 })
 if err!=nil{return Result{},err}
 proxyURL,err:=egress.Start()
 if err!=nil{return Result{},err}
 defer egress.Close()
 factory:=ApprovedChromiumFactory{
  Executable:os.Getenv("BUNNY_CHROME"),ProxyURL:proxyURL,
  Headless:headless,Scope:scope,
 }
 var otp OTPProvider
 if cfg.UseEmailOTP||cfg.UseMagicLink{
  otp,err=NewIMAPOTP(cfg.Mailboxes,secrets)
  if err!=nil{return Result{},err}
 }else if cfg.UseTOTP{
  otp=OwnedTOTP{Secrets:secrets}
 }
 return RunAdaptive(ctx,cfg,scope,manifest,factory,secrets,otp,operator)
}
