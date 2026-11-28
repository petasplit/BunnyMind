// Package bunnycrawl performs bounded, read-only, same-origin crawling
// inside an operator-owned BunnyGuard engagement. It is not an exploit engine.
package bunnycrawl

import (
 "context"
 "crypto/sha256"
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
 "time"

 "golang.org/x/net/html"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnynet"
 "github.com/enowdev/antares/internal/bunnyquota"
)

const MaxPages=16
type Plan struct{
 EngagementID string `json:"engagement_id"`
 SeedURL string `json:"seed_url"`
 MaxPages int `json:"max_pages"`
 MaxDepth int `json:"max_depth"`
}
type Page struct{
 Path string `json:"path"`
 Status int `json:"status"`
 ContentType string `json:"content_type,omitempty"`
 BodySHA256 string `json:"body_sha256"`
 Bytes int `json:"bytes"`
 Truncated bool `json:"truncated"`
 Discovered int `json:"discovered"`
}
type Summary struct{
 EngagementID string `json:"engagement_id"`
 SeedOrigin string `json:"seed_origin"`
 StartedUTC string `json:"started_utc"`
 FinishedUTC string `json:"finished_utc"`
 Pages []Page `json:"pages"`
 DiscoveredPaths []string `json:"discovered_paths"`
 RequestsUsed int `json:"requests_used"`
 StopReason string `json:"stop_reason"`
 Note string `json:"note"`
}
func sameOrigin(a,b *url.URL)bool{
 return strings.EqualFold(a.Scheme,b.Scheme)&&strings.EqualFold(a.Host,b.Host)
}
func Validate(p Plan,guard bunnyguard.Policy)error{
 if p.EngagementID!=guard.EngagementID||p.MaxPages<1||p.MaxPages>MaxPages||
  p.MaxPages>guard.MaxNetworkCalls||p.MaxDepth<0||p.MaxDepth>3{
  return errors.New("crawl plan exceeds operator-approved engagement")
 }
 u,err:=url.Parse(p.SeedURL)
 if err!=nil||u==nil||u.User!=nil||u.Fragment!=""||
  u.Scheme==""||u.Host==""||u.RawQuery!=""{
  return errors.New("crawl seed must be an absolute scope origin/path without query or credentials")
 }
 allowed:=false
 for _,raw:=range guard.AllowedOrigins{
  a,e:=url.Parse(raw)
  if e==nil&&sameOrigin(u,a){allowed=true;break}
 }
 if !allowed{return errors.New("crawl seed is not among explicitly approved origins")}
 getAllowed:=len(guard.AllowedMethods)==0
 for _,m:=range guard.AllowedMethods{if strings.EqualFold(m,"GET"){getAllowed=true}}
 if !getAllowed{return errors.New("GET not permitted by engagement")}
 if strings.HasPrefix(u.Path,"//")||strings.Contains(strings.ToLower(u.EscapedPath()),"%2e")||
  strings.Contains(strings.ToLower(u.EscapedPath()),"%2f")||strings.Contains(strings.ToLower(u.EscapedPath()),"%5c"){
  return errors.New("unsafe encoded crawl path")
 }
 return nil
}
func harmfulPath(raw string)bool{
 p:=strings.ToLower(raw)
 for _,part:=range []string{"/logout","/log_out","/signout","/delete","/destroy","/unsubscribe","/checkout","/purchase","/payment","/cancel","/reset","/disable","/shutdown","/terminate"}{
  if strings.Contains(p,part){return true}
 }
 return false
}
func permittedLink(seed *url.URL,base *url.URL,raw string)(string,bool){
 raw=strings.TrimSpace(raw)
 if len(raw)>2048||raw==""||strings.HasPrefix(raw,"#")||strings.HasPrefix(raw,"javascript:")||
  strings.HasPrefix(raw,"data:")||strings.HasPrefix(raw,"mailto:")||strings.HasPrefix(raw,"tel:"){
  return "",false
 }
 link,err:=url.Parse(raw)
 if err!=nil||link==nil||link.User!=nil||link.Opaque!=""{return "",false}
 resolved:=base.ResolveReference(link)
 if !sameOrigin(seed,resolved)||harmfulPath(resolved.Path){return "",false}
 if strings.HasPrefix(resolved.Path,"//")||strings.Contains(strings.ToLower(resolved.EscapedPath()),"%2e")||
  strings.Contains(strings.ToLower(resolved.EscapedPath()),"%2f")||strings.Contains(strings.ToLower(resolved.EscapedPath()),"%5c"){return "",false}
 ext:=strings.ToLower(path.Ext(resolved.Path))
 switch ext{
 case ".jpg",".jpeg",".png",".gif",".webp",".svg",".pdf",".zip",".exe",".woff",".woff2",".ttf",".mp4",".mp3",".ico":return "",false
 }
 resolved.RawQuery=""
 resolved.Fragment=""
 return resolved.String(),true
}
func linksHTML(seed *url.URL,base *url.URL,src []byte)[]string{
 root,err:=html.Parse(strings.NewReader(string(src)))
 if err!=nil{return nil}
 seen:=map[string]bool{}
 var walk func(*html.Node)
 walk=func(n *html.Node){
  if n.Type==html.ElementNode{
   switch n.Data {case "script","style","template":}
   if n.Data=="a"||n.Data=="link"||n.Data=="script"||n.Data=="iframe"{
    for _,attr:=range n.Attr{
     if attr.Key!="href"&&attr.Key!="src"{continue}
     if resolved,ok:=permittedLink(seed,base,attr.Val);ok{seen[resolved]=true}
    }
   }
  }
  for ch:=n.FirstChild;ch!=nil;ch=ch.NextSibling{walk(ch)}
 }
 walk(root)
 out:=make([]string,0,len(seen))
 for v:=range seen{out=append(out,v)}
 sort.Strings(out)
 return out
}
func sha(raw []byte)string{sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:])}
func writeSummary(folder string,s Summary)error{
 if err:=os.MkdirAll(folder,0700);err!=nil{return err}
 raw,err:=json.MarshalIndent(s,"","  ")
 if err!=nil{return err}
 fd,err:=os.OpenFile(filepath.Join(folder,"crawl.json"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return err}
 if _,err=fd.Write(raw);err!=nil{_ = fd.Close();return err}
 return fd.Close()
}
func Run(ctx context.Context,p Plan,guard bunnyguard.Policy,evidenceRoot string)(Summary,error){
 if err:=Validate(p,guard);err!=nil{return Summary{},err}
 if strings.TrimSpace(evidenceRoot)==""{return Summary{},errors.New("evidence directory required")}
 seed,_:=url.Parse(p.SeedURL)
 rootOrigin:=seed.Scheme+"://"+seed.Host
 reader,err:=bunnynet.New(bunnynet.Policy{Origins:guard.AllowedOrigins,PrivateCIDRs:guard.AllowedCIDRs})
 if err!=nil{return Summary{},err}
 // One active crawler at a time for a given engagement/evidence root. Shared
 // worst-case reservation prevents the Python proof campaign from silently
 // consuming an overlapping budget when it uses the same directory.
 release,err:=bunnyquota.ExecutionLease(ctx,evidenceRoot,p.EngagementID)
 if err!=nil{return Summary{},err}
 defer release()
 if _,err:=bunnyquota.Reserve(ctx,evidenceRoot,p.EngagementID,p.MaxPages,guard.MaxNetworkCalls);err!=nil{return Summary{},err}
 begun:=time.Now().UTC()
 out:=Summary{EngagementID:p.EngagementID,SeedOrigin:rootOrigin,
  StartedUTC:begun.Format(time.RFC3339Nano),Pages:[]Page{},DiscoveredPaths:[]string{},
  Note:"Read-only, same-origin, no redirects/cookies/form submission. The crawler is not an exploit verifier. Discovered links are candidates, not independently verified vulnerabilities.",
 }
 type item struct{URL string;Depth int}
 queue:=[]item{{URL:p.SeedURL,Depth:0}}
 seen:=map[string]bool{}
 discovered:=map[string]bool{}
 agent:=guard.UserAgent
 if strings.TrimSpace(agent)==""{agent="BunnyMind-ScopedCrawler/0.33"}
 pace:=guard.MinIntervalMS
 if pace<250{pace=250}
 for len(queue)>0&&len(out.Pages)<p.MaxPages{
  if err:=ctx.Err();err!=nil{out.StopReason="cancelled";break}
  current:=queue[0];queue=queue[1:]
  if seen[current.URL]{continue}
  seen[current.URL]=true
  if len(out.Pages)>0{
   select{case <-ctx.Done():out.StopReason="cancelled";break
   case <-time.After(time.Duration(pace)*time.Millisecond):}
  }
  meta,body,err:=reader.ReadDocument(ctx,current.URL,agent,65536)
  if err!=nil{out.StopReason="transport_error";break}
  parsed,_:=url.Parse(current.URL)
  record:=Page{Path:parsed.EscapedPath(),Status:meta.Status,ContentType:meta.ContentType,
   BodySHA256:meta.BodySHA256,Bytes:meta.BytesRead,Truncated:meta.Truncated}
  out.RequestsUsed++
  if current.Depth<p.MaxDepth&&!meta.Truncated&&meta.Status==200&&strings.Contains(strings.ToLower(meta.ContentType),"html"){
   hrefs:=linksHTML(seed,parsed,body)
   record.Discovered=len(hrefs)
   for _,href:=range hrefs{
    next,_:=url.Parse(href)
    discovered[next.EscapedPath()]=true
    if !seen[href]&&len(queue)<64{queue=append(queue,item{URL:href,Depth:current.Depth+1})}
   }
  }
  out.Pages=append(out.Pages,record)
 }
 for v:=range discovered{out.DiscoveredPaths=append(out.DiscoveredPaths,v)}
 sort.Strings(out.DiscoveredPaths)
 if len(out.DiscoveredPaths)>100{out.DiscoveredPaths=out.DiscoveredPaths[:100]}
 if out.StopReason==""{
  if len(out.Pages)==p.MaxPages{out.StopReason="max_pages"}
  else{out.StopReason="frontier_exhausted"}
 }
 out.FinishedUTC=time.Now().UTC().Format(time.RFC3339Nano)
 folder:=filepath.Join(evidenceRoot,fmt.Sprintf("crawl_%s_%d",sha([]byte(p.EngagementID+"|"+p.SeedURL))[:16],time.Now().UnixNano()))
 if err:=writeSummary(folder,out);err!=nil{return out,fmt.Errorf("cannot write private crawl summary: %w",err)}
 return out,nil
}
