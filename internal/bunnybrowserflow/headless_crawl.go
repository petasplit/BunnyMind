package bunnybrowserflow

import (
 "context"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net/url"
 "os"
 "path"
 "path/filepath"
 "sort"
 "strings"
 "sync"
 "time"

 "github.com/enowdev/antares/internal/browser"
 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnyegress"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyquota"
)

type HeadlessCrawlConfig struct {
 Origin string `json:"origin"`
 StartPath string `json:"start_path"`
 MaxPages int `json:"max_pages"`
 MaxDepth int `json:"max_depth"`
}
type HeadlessEndpoint struct {
 Path string `json:"path"`
 Method string `json:"method"`
 Source string `json:"source"`
 SHA256 string `json:"sha256"`
}
type HeadlessPage struct {
 Path string `json:"path"`
 TitleSHA256 string `json:"title_sha256"`
 DiscoveredLinks int `json:"discovered_links"`
 ObservedRequests int `json:"observed_requests"`
 ScriptBodiesInspected int `json:"script_bodies_inspected"`
}
type HeadlessReport struct {
 EngagementID string `json:"engagement_id"`
 Origin string `json:"origin"`
 StartedUTC string `json:"started_utc"`
 CompletedUTC string `json:"completed_utc"`
 AuthStepsCompleted int `json:"auth_steps_completed"`
 Pages []HeadlessPage `json:"pages"`
 Endpoints []HeadlessEndpoint `json:"endpoints"`
 EncryptedCaptures []bunnyartifact.Receipt `json:"encrypted_captures,omitempty"`
 StopReason string `json:"stop_reason"`
 EvidenceFile string `json:"evidence_file,omitempty"`
 Limitation string `json:"limitation"`
}
func digestHeadless(data string)string{h:=sha256.Sum256([]byte(data));return hex.EncodeToString(h[:])}
func ValidateHeadlessConfig(cfg HeadlessCrawlConfig,login Plan,scope ApprovedScope,guard bunnyguard.Policy)error {
 allowed,err:=ValidateApprovedScope(scope,guard)
 if err!=nil{return err}
 origin,err:=strictOrigin(cfg.Origin)
 if err!=nil||!allowed[origin]||login.Origin!=origin {return errors.New("headless crawl and login require the same reviewed HTTPS origin")}
 if err:=validateSteps(login);err!=nil{return err}
 if err:=actorBudget(login,scope,guard);err!=nil{return err}
 if cfg.MaxPages<1||cfg.MaxPages>8||cfg.MaxDepth<0||cfg.MaxDepth>2||
  cfg.MaxPages*3>scope.MaxBrowserRequests {return errors.New("headless crawl page/depth/network budget exceeded")}
 if !safePath(cfg.StartPath){return errors.New("headless crawl requires a safe approved start path")}
 actors:=map[string]bool{}
 for _,step:=range login.Steps{
  actors[step.Actor]=true
  if step.Op==OpHandoff{return errors.New("headless crawl cannot complete unapproved MFA, CAPTCHA or passkey challenges")}
 }
 if len(actors)!=1||login.Steps[len(login.Steps)-1].Op!=OpAssert{
  return errors.New("headless crawl requires one approved test identity and a terminal logged-in assertion")
 }
 return nil
}
type headlessDriver interface {
 Navigate(context.Context,string)error
 Eval(context.Context,string)(json.RawMessage,error)
 URL(context.Context)(string,error)
 DrainNetwork(context.Context)[]browser.NetworkRequest
 ResponseBody(context.Context,string)(string,string,error)
}
func cleanedPath(uri string)string{
 u,err:=url.Parse(uri)
 if err!=nil{return "/"}
 p:=u.EscapedPath()
 if p==""{p="/"}
 segments:=strings.Split(p,"/")
 for i,x:=range segments{
  if len(x)>32||(len(x)>12&&isOnlyDigits(x)){segments[i]="{id}"}
 }
 return strings.Join(segments,"/")
}
func isOnlyDigits(s string)bool{
 if s==""{return false}
 for _,r:=range s{if r<'0'||r>'9'{return false}}
 return true
}
func appendEndpoint(report *HeadlessReport,seen map[string]bool,origin,raw,method,source string){
 canonical,ok:=safeDiscoveryPath(origin,raw)
 if !ok{return}
 if len(report.Endpoints)>=256{return}
 if method!="GET"&&method!="HEAD"{method="OBSERVED"}
 parsed,_:=url.Parse(canonical)
 key:=method+"|"+parsed.EscapedPath()+"|"+source
 if seen[key]{return}
 seen[key]=true
 report.Endpoints=append(report.Endpoints,HeadlessEndpoint{
  Path:cleanedPath(canonical),Method:method,Source:source,SHA256:digestHeadless(key),
 })
}
func scriptFromBody(raw,kind string)(string,bool){
 if strings.HasPrefix(kind,"application/base64;"){
  blob,err:=base64.StdEncoding.DecodeString(raw)
  if err!=nil||len(blob)>48*1024{return "",false}
  return string(blob),true
 }
 if len(raw)>48*1024{return "",false}
 return raw,true
}
// crawlRendered keeps a single authenticated browser profile, performs only
// safe same-origin navigation, and extracts static JS references plus observed
// script/XHR metadata. It never clicks controls or submits a form.
func crawlRendered(ctx context.Context,d headlessDriver,cfg HeadlessCrawlConfig,
 capture func(context.Context,int,[]browser.NetworkRequest)(bunnyartifact.Receipt,error))(HeadlessReport,error){
 report:=HeadlessReport{Origin:cfg.Origin,StartedUTC:time.Now().UTC().Format(time.RFC3339Nano),
  Pages:[]HeadlessPage{},Endpoints:[]HeadlessEndpoint{},EncryptedCaptures:[]bunnyartifact.Receipt{},
  Limitation:"Passive DOM and JavaScript endpoint references plus CDP network metadata; these are candidates, not verified vulnerabilities. No forms or controls are triggered in crawl phase.",
 }
 type item struct{URL string;Depth int}
 queued:=[]item{{URL:cfg.Origin+cfg.StartPath,Depth:0}}
 seenPages:=map[string]bool{}
 seenEndpoints:=map[string]bool{}
 for len(queued)>0&&len(report.Pages)<cfg.MaxPages{
  if err:=ctx.Err();err!=nil{return report,err}
  item:=queued[0];queued=queued[1:]
  if seenPages[item.URL]{continue}
  seenPages[item.URL]=true
  if err:=d.Navigate(ctx,item.URL);err!=nil{
   report.StopReason="navigation_failed"
   return report,fmt.Errorf("headless navigation did not complete: %w",err)
  }
  actual,err:=d.URL(ctx)
  if err!=nil||!sameHTTPSOrigin(cfg.Origin,actual){return report,errors.New("browser navigated outside exact approved origin")}
  raw,err:=d.Eval(ctx,discoveryJS)
  if err!=nil{return report,errors.New("headless DOM inspection failed")}
  discovery,err:=parseDiscovery(raw)
  if err!=nil{return report,err}
  one:=HeadlessPage{Path:cleanedPath(actual)}
  for _,v:=range discovery.InlineScripts{
   for _,found:=range scriptEndpoints(v,cfg.Origin,40){appendEndpoint(&report,seenEndpoints,cfg.Origin,found,"OBSERVED","inline_js_candidate")}
  }
  for _,v:=range discovery.ObservedResources{
   appendEndpoint(&report,seenEndpoints,cfg.Origin,v,"OBSERVED","performance_resource")
  }
  requests:=d.DrainNetwork(ctx)
  one.ObservedRequests=len(requests)
  for _,req:=range requests{
   if !sameHTTPSOrigin(cfg.Origin,req.URL){continue}
   appendEndpoint(&report,seenEndpoints,cfg.Origin,req.URL,req.Method,"browser_network")
   if req.ResourceType!="Script"||req.Response==nil||one.ScriptBodiesInspected>=8||
    req.RequestID==""{continue}
   src,kind,err:=d.ResponseBody(ctx,req.RequestID)
   if err!=nil{continue}
   script,ok:=scriptFromBody(src,kind)
   if !ok{continue}
   one.ScriptBodiesInspected++
   for _,found:=range scriptEndpoints(script,cfg.Origin,40){appendEndpoint(&report,seenEndpoints,cfg.Origin,found,"OBSERVED","script_body_candidate")}
  }
  if capture!=nil{
   receipt,err:=capture(ctx,len(report.Pages)+1,requests)
   if err!=nil{return report,errors.New("encrypted Chromium HTTP evidence unavailable")}
   if receipt.File!=""{report.EncryptedCaptures=append(report.EncryptedCaptures,receipt)}
  }
  if item.Depth<cfg.MaxDepth{
   for _,href:=range discovery.Links{
    safe,ok:=safeDiscoveryPath(cfg.Origin,href)
    if !ok{continue}
    ext:=strings.ToLower(path.Ext(cleanedPath(safe)))
    switch ext{
    case ".js",".css",".png",".jpg",".svg",".woff",".woff2",".pdf",".zip",".mp4":continue
    }
    one.DiscoveredLinks++
    appendEndpoint(&report,seenEndpoints,cfg.Origin,safe,"GET","dom_link")
    if !seenPages[safe]&&len(queued)<48{queued=append(queued,item{URL:safe,Depth:item.Depth+1})}
   }
  }
  for _,v:=range discovery.ScriptURLs{appendEndpoint(&report,seenEndpoints,cfg.Origin,v,"GET","script_src")}
  one.TitleSHA256=digestHeadless(one.Path) // no page text or title is persisted
  report.Pages=append(report.Pages,one)
 }
 sort.Slice(report.Endpoints,func(i,j int)bool{
  if report.Endpoints[i].Path==report.Endpoints[j].Path{return report.Endpoints[i].Source<report.Endpoints[j].Source}
  return report.Endpoints[i].Path<report.Endpoints[j].Path
 })
 if len(report.Pages)==cfg.MaxPages{report.StopReason="max_pages"}else{report.StopReason="frontier_exhausted"}
 report.CompletedUTC=time.Now().UTC().Format(time.RFC3339Nano)
 return report,nil
}

type retainedBrowser struct{ Browser }
func (retainedBrowser) Close(){}
type retainedFactory struct{
 inner ApprovedChromiumFactory
 mu sync.Mutex
 drivers map[string]*chromeDriver
 vault *screenshotVault
}
func (r *retainedFactory) New(ctx context.Context,actor,origin string)(Browser,error){
 b,err:=r.inner.New(ctx,actor,origin)
 if err!=nil{return nil,err}
 d,ok:=b.(*chromeDriver)
 if !ok{b.Close();return nil,errors.New("unexpected Chromium driver type")}
 d.vault=r.vault
 r.mu.Lock()
 r.drivers[actor]=d
 r.mu.Unlock()
 return retainedBrowser{Browser:b},nil
}
func (r *retainedFactory) Close(){
 r.mu.Lock();defer r.mu.Unlock()
 for _,d:=range r.drivers{d.Close()}
}
// RunConfiguredHeadlessCrawl first executes an operator-approved keyring-only
// login flow in a fresh Chromium. It then irreversibly switches the CDP gate
// to read-only, keeping that same authenticated profile for bounded crawling.
func RunConfiguredHeadlessCrawl(ctx context.Context,scope ApprovedScope,login Plan,
 cfg HeadlessCrawlConfig,manifest bunnyguard.Policy,evidenceRoot string)(HeadlessReport,error){
 if err:=ValidateHeadlessConfig(cfg,login,scope,manifest);err!=nil{return HeadlessReport{},err}
 if strings.TrimSpace(evidenceRoot)==""||len(evidenceRoot)>2048{return HeadlessReport{},errors.New("private evidence output directory required")}
 // Worst-case reserve all browser requests before any browser activity; a
 // concurrent Python/crawler runner using this root cannot reuse the budget.
 lease,err:=bunnyquota.ExecutionLease(ctx,evidenceRoot,manifest.EngagementID)
 if err!=nil{return HeadlessReport{},err}
 defer lease()
 if _,err:=bunnyquota.Reserve(ctx,evidenceRoot,manifest.EngagementID,
  scope.MaxBrowserRequests,manifest.MaxNetworkCalls);err!=nil{return HeadlessReport{},err}
 vault,err:=newCaptureVault(evidenceRoot,manifest.EngagementID)
 if err!=nil{return HeadlessReport{},errors.New("private encrypted browser vault or local key unavailable")}
 proxy,err:=bunnyegress.New(bunnyegress.Config{Origins:scope.AllowedOrigins,MaxTunnels:scope.MaxTunnels})
 if err!=nil{return HeadlessReport{},err}
 address,err:=proxy.Start()
 if err!=nil{return HeadlessReport{},err}
 defer proxy.Close()
 factory:=&retainedFactory{
  inner:ApprovedChromiumFactory{Executable:os.Getenv("BUNNY_CHROME"),Headless:true,ProxyURL:address,Scope:scope},
  drivers:map[string]*chromeDriver{},vault:vault,
 }
 defer factory.Close()
 auth,err:=RunApproved(ctx,login,scope,factory,KeyringSecrets{},nil,manifest)
 if err!=nil{return HeadlessReport{},fmt.Errorf("approved test-account login not complete: %w",err)}
 actor:=login.Steps[0].Actor
 driver:=factory.drivers[actor]
 if driver==nil{return HeadlessReport{},errors.New("approved test persona browser was not retained")}
 if err:=driver.session.LockExternalReadOnly();err!=nil{return HeadlessReport{},err}
 // Discard authentication-stage traffic; all subsequent private evidence is
 // captured under the read-only crawl phase, with no form-body replay.
 _=driver.session.DrainNetwork(ctx)
 report,err:=crawlRendered(ctx,driver.session,cfg,
  func(ctx context.Context,step int,requests []browser.NetworkRequest)(bunnyartifact.Receipt,error){
   return driver.captureBrowserRaw(ctx,actor,100+step,requests,map[string]bool{cfg.Origin:true})
  })
 if err!=nil{return report,err}
 report.EngagementID=manifest.EngagementID
 report.AuthStepsCompleted=auth.StepsCompleted
 root:=filepath.Join(evidenceRoot,manifest.EngagementID)
 if err:=os.MkdirAll(root,0700);err!=nil{return report,err}
 file:=filepath.Join(root,fmt.Sprintf("headless-crawl-%d.json",time.Now().UnixNano()))
 encoded,err:=json.MarshalIndent(report,"","  ")
 if err!=nil{return report,err}
 if err:=os.WriteFile(file,encoded,0600);err!=nil{return report,err}
 report.EvidenceFile=file
 return report,nil
}
