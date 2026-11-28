package bunnybrowserflow

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnyguard"
)

// Replay is a *fresh-login recipe*, never a serialized Chromium profile.
// No cookies, tokens, LocalStorage, IndexedDB or credential values are
// exported. Both runs create independent ephemeral Chromium profiles.
type ReplayOutcome struct {
 EngagementID string `json:"engagement_id"`
 Origin string `json:"origin"`
 Outcome string `json:"outcome"`
 FirstFingerprint string `json:"first_fingerprint"`
 SecondFingerprint string `json:"second_fingerprint"`
 FirstEvidenceFile string `json:"first_evidence_file,omitempty"`
 SecondEvidenceFile string `json:"second_evidence_file,omitempty"`
 EncryptedCapsule bunnyartifact.Receipt `json:"encrypted_capsule"`
 FreshBrowserProfiles int `json:"fresh_browser_profiles"`
 ImpactVerified bool `json:"impact_verified"`
 Limitations string `json:"limitations"`
}
type replayCapsule struct{
 Version int `json:"version"`
 EngagementID string `json:"engagement_id"`
 Origin string `json:"origin"`
 LoginPlanSHA256 string `json:"login_plan_sha256"`
 ScopeSHA256 string `json:"scope_sha256"`
 CrawlConfigSHA256 string `json:"crawl_config_sha256"`
 CapturedAt string `json:"captured_at"`
 FirstFingerprint string `json:"first_fingerprint"`
 SecondFingerprint string `json:"second_fingerprint"`
 FirstEvidenceFile string `json:"first_evidence_file"`
 SecondEvidenceFile string `json:"second_evidence_file"`
}
func stableFingerprint(report HeadlessReport)(string,error){
 if len(report.Pages)==0||report.AuthStepsCompleted==0{return "",errors.New("missing completed authenticated crawl")}
 paths:=make([]string,0,len(report.Pages))
 for _,page:=range report.Pages{paths=append(paths,page.Path)}
 sort.Strings(paths)
 endpoints:=make([]string,0,len(report.Endpoints))
 for _,e:=range report.Endpoints{endpoints=append(endpoints,e.Method+"|"+e.Path+"|"+e.Source)}
 sort.Strings(endpoints)
 raw,err:=json.Marshal(struct{
  Origin string `json:"origin"`
  Steps int `json:"steps"`
  Paths []string `json:"paths"`
  Endpoints []string `json:"endpoints"`
 }{report.Origin,report.AuthStepsCompleted,paths,endpoints})
 if err!=nil{return "",err}
 h:=sha256.Sum256(raw)
 return hex.EncodeToString(h[:]),nil
}
func jsonHash(v any)(string,error){
 b,err:=json.Marshal(v)
 if err!=nil{return "",err}
 sum:=sha256.Sum256(b)
 return hex.EncodeToString(sum[:]),nil
}
func replayWith(ctx context.Context,scope ApprovedScope,login Plan,cfg HeadlessCrawlConfig,
 manifest bunnyguard.Policy,root string,runner func(context.Context)(HeadlessReport,error))(ReplayOutcome,error){
 if err:=ValidateHeadlessConfig(cfg,login,scope,manifest);err!=nil{return ReplayOutcome{},err}
 if scope.MaxBrowserRequests>manifest.MaxNetworkCalls/2{
  return ReplayOutcome{},errors.New("reviewed engagement cannot cover two independently budgeted browser runs")
 }
 if runner==nil{return ReplayOutcome{},errors.New("fresh authenticated browser runner required")}
 out:=ReplayOutcome{
  EngagementID:manifest.EngagementID,Origin:cfg.Origin,FreshBrowserProfiles:0,
  ImpactVerified:false,
  Limitations:"Two fresh credential-backed sign-ins are independently executed in new Chromium profiles. Matching endpoint inventories do not establish an exploitable vulnerability or prove equivalent session tokens. A changed application may legitimately diverge.",
 }
 var runs [2]HeadlessReport
 for i:=0;i<2;i++{
  if err:=ctx.Err();err!=nil{return out,err}
  run,err:=runner(ctx)
  if err!=nil{return out,fmt.Errorf("fresh authenticated browser replay pass %d failed: %w",i+1,err)}
  if run.EngagementID!=manifest.EngagementID||run.Origin!=cfg.Origin{return out,errors.New("replay did not return authenticated in-scope report")}
  runs[i]=run
  out.FreshBrowserProfiles++
 }
 first,err:=stableFingerprint(runs[0]);if err!=nil{return out,err}
 second,err:=stableFingerprint(runs[1]);if err!=nil{return out,err}
 out.FirstFingerprint=first
 out.SecondFingerprint=second
 out.FirstEvidenceFile=runs[0].EvidenceFile
 out.SecondEvidenceFile=runs[1].EvidenceFile
 out.Outcome="authenticated_state_diverged"
 if first==second{out.Outcome="authenticated_inventory_reproduced"}
 planDigest,_:=jsonHash(login)
 scopeDigest,_:=jsonHash(scope)
 crawlDigest,_:=jsonHash(cfg)
 capsule:=replayCapsule{Version:1,EngagementID:manifest.EngagementID,Origin:cfg.Origin,
  LoginPlanSHA256:planDigest,ScopeSHA256:scopeDigest,CrawlConfigSHA256:crawlDigest,
  CapturedAt:time.Now().UTC().Format(time.RFC3339Nano),
  FirstFingerprint:first,SecondFingerprint:second,
  FirstEvidenceFile:runs[0].EvidenceFile,SecondEvidenceFile:runs[1].EvidenceFile,
 }
 data,err:=json.Marshal(capsule)
 if err!=nil{return out,err}
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return out,errors.New("OS-owned evidence encryption key required for replay capsule")}
 if root==""||len(root)>2048{return out,errors.New("private replay evidence path required")}
 dest:=filepath.Join(root,manifest.EngagementID)
 if err:=os.MkdirAll(dest,0700);err!=nil{return out,err}
 name:=fmt.Sprintf("browser-replay-%d",time.Now().UnixNano())
 receipt,err:=bunnyartifact.Store(dest,name,"browser_replay",data,key)
 if err!=nil{return out,err}
 out.EncryptedCapsule=receipt
 return out,nil
}
// ReplayApprovedFreshState never copies an authenticated browser profile. It
// reauthenticates with the same operator-owned plan and isolated fresh Chrome
// twice and preserves private encrypted provenance for both runs.
func ReplayApprovedFreshState(ctx context.Context,scope ApprovedScope,login Plan,cfg HeadlessCrawlConfig,
 manifest bunnyguard.Policy,root string)(ReplayOutcome,error){
 return replayWith(ctx,scope,login,cfg,manifest,root,func(ctx context.Context)(HeadlessReport,error){
  return RunConfiguredHeadlessCrawl(ctx,scope,login,cfg,manifest,root)
 })
}
func ReviewReplayCapsule(folder,name string,key []byte)(ReplayOutcome,error){
 if !strings.HasPrefix(name,"browser-replay-")||strings.Contains(name,".."){
  return ReplayOutcome{},errors.New("invalid replay capsule filename")
 }
 raw,err:=bunnyartifact.Open(folder,name,"browser_replay",key)
 if err!=nil{return ReplayOutcome{},err}
 var c replayCapsule
 if err:=json.Unmarshal(raw,&c);err!=nil||c.Version!=1||c.EngagementID==""||
  c.FirstFingerprint==""||c.SecondFingerprint==""{
  return ReplayOutcome{},errors.New("invalid replay capsule")
 }
 status:="authenticated_state_diverged"
 if c.FirstFingerprint==c.SecondFingerprint{status="authenticated_inventory_reproduced"}
 return ReplayOutcome{
  EngagementID:c.EngagementID,Origin:c.Origin,Outcome:status,
  FirstFingerprint:c.FirstFingerprint,SecondFingerprint:c.SecondFingerprint,
  FirstEvidenceFile:c.FirstEvidenceFile,SecondEvidenceFile:c.SecondEvidenceFile,
  ImpactVerified:false,FreshBrowserProfiles:2,
  Limitations:"This opens an authenticated encrypted replay recipe only. It contains no live sessions and does not independently prove impact.",
 },nil
}
