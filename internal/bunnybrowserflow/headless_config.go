package bunnybrowserflow

import (
 "errors"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
)

// LoadHeadlessConfiguration validates the three trusted local operator-owned
// files together with the active BunnyGuard manifest, before any login or
// external connection is attempted. There is no model-supplied URL or secret.
func LoadHeadlessConfiguration(guardFile,scopeFile,loginFile,crawlFile string)(ApprovedScope,Plan,HeadlessCrawlConfig,bunnyguard.Policy,error){
 if strings.TrimSpace(guardFile)==""||strings.TrimSpace(scopeFile)==""||
  strings.TrimSpace(loginFile)==""||strings.TrimSpace(crawlFile)==""{
  return ApprovedScope{},Plan{},HeadlessCrawlConfig{},bunnyguard.Policy{},errors.New("reviewed BunnyGuard, browser scope, login plan and headless crawl configuration are all required")
 }
 guard,err:=bunnyguard.New(guardFile)
 if err!=nil{return ApprovedScope{},Plan{},HeadlessCrawlConfig{},bunnyguard.Policy{},err}
 var scope ApprovedScope
 if err:=loadJSON(scopeFile,&scope);err!=nil{return ApprovedScope{},Plan{},HeadlessCrawlConfig{},bunnyguard.Policy{},err}
 var login Plan
 if err:=loadJSON(loginFile,&login);err!=nil{return ApprovedScope{},Plan{},HeadlessCrawlConfig{},bunnyguard.Policy{},err}
 var crawl HeadlessCrawlConfig
 if err:=loadJSON(crawlFile,&crawl);err!=nil{return ApprovedScope{},Plan{},HeadlessCrawlConfig{},bunnyguard.Policy{},err}
 manifest:=guard.Manifest()
 if err:=ValidateHeadlessConfig(crawl,login,scope,manifest);err!=nil{
  return ApprovedScope{},Plan{},HeadlessCrawlConfig{},bunnyguard.Policy{},err
 }
 return scope,login,crawl,manifest,nil
}
