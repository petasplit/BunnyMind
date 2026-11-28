package bunnybrowserflow

import (
 "encoding/json"
 "errors"
 "net/url"
 "regexp"
 "sort"
 "strings"
)

type BrowserDiscovery struct {
 Links []string `json:"links"`
 ScriptURLs []string `json:"script_urls"`
 InlineScripts []string `json:"inline_scripts"`
 ObservedResources []string `json:"observed_resources"`
}
// Executed inside the trusted Chromium context. It only *reads* rendered
// navigation links, script contents and browser resource timing metadata.
// It does not click controls, submit forms, read cookies, localStorage,
// Authorization headers, input values or page-private text.
const discoveryJS = `(() => {
 const unique = (items, cap) => [...new Set(items.filter(x=>typeof x==="string"&&x.length<2048))].slice(0,cap);
 const links = [...document.querySelectorAll('a[href]')].slice(0,128).map(a=>a.href);
 const scriptURLs = [...document.scripts].slice(0,64).map(a=>a.src).filter(Boolean);
 const inlineScripts = [...document.scripts].filter(a=>!a.src)
   .slice(0,12).map(a=>(a.textContent||"").slice(0,3000));
 const observedResources=performance.getEntriesByType("resource")
   .filter(r=>["fetch","xmlhttprequest","script"].includes(r.initiatorType))
   .slice(0,128).map(r=>r.name);
 return {links:unique(links,128),script_urls:unique(scriptURLs,64),
    inline_scripts:inlineScripts,observed_resources:unique(observedResources,128)};
})()`

var jsPathPatterns = []*regexp.Regexp{
 regexp.MustCompile(`(?i)\b(?:fetch|axios\.(?:get|post|put|delete|patch)|import)\s*\(\s*["'](/[^"'\s?#]{1,180})["']`),
 regexp.MustCompile(`(?i)\b(?:url|endpoint|path|baseURL)\s*[:=]\s*["'](/(?:api|graphql|v[0-9]+|internal|rest)/[^"'\s?#]{0,180})["']`),
 regexp.MustCompile(`(?i)\b(?:fetch|open)\s*\(\s*["'](https?://[^"'\s?#]{1,240})["']`),
}
func parseDiscovery(raw []byte)(BrowserDiscovery,error){
 var d BrowserDiscovery
 if len(raw)==0||len(raw)>160*1024{return d,errors.New("browser discovery JSON missing or oversized")}
 if err:=json.Unmarshal(raw,&d);err!=nil{return d,err}
 if len(d.Links)>128||len(d.ScriptURLs)>64||len(d.InlineScripts)>12||len(d.ObservedResources)>128{return d,errors.New("browser discovery collection unbounded")}
 for _,v:=range d.InlineScripts{if len(v)>3000{return d,errors.New("browser inline script exceeds per-element limit")}}
 return d,nil
}
func sameHTTPSOrigin(origin,raw string)bool{
 base,e:=url.Parse(origin)
 if e!=nil||base==nil{return false}
 u,e:=url.Parse(raw)
 if e!=nil||u==nil||u.User!=nil||u.Opaque!=""||u.Scheme!="https"||u.Hostname()==""||
  (u.Port()!=""&&u.Port()!="443"){return false}
 return strings.EqualFold(base.Hostname(),u.Hostname())&&base.Scheme==u.Scheme
}
func safeDiscoveryPath(origin,raw string)(string,bool){
 if len(raw)>2048||!sameHTTPSOrigin(origin,raw){return "",false}
 u,e:=url.Parse(raw)
 if e!=nil||u==nil||strings.Contains(u.EscapedPath(),"%")||strings.HasPrefix(u.Path,"//"){return "",false}
 path:=u.EscapedPath()
 if path==""{path="/"}
 if strings.Contains(path,"\\")||strings.Contains(path,".."){return "",false}
 lower:=strings.ToLower(path)
 for _,bad:=range []string{"/logout","/signout","/delete","/destroy","/unsubscribe","/payment","/purchase","/checkout","/reset","/cancel","/terminate","/disable"}{
  if strings.Contains(lower,bad){return "",false}
 }
 // Strip query, fragments and dynamic credentials or user IDs.
 u.RawQuery="";u.Fragment=""
 return u.Scheme+"://"+u.Host+path,true
}
func scriptEndpoints(src string,origin string,limit int)[]string{
 if limit<1||limit>100{return nil}
 if len(src)>48*1024{src=src[:48*1024]}
 seen:=map[string]bool{}
 for _,regex:=range jsPathPatterns{
  for _,match:=range regex.FindAllStringSubmatch(src,limit*3){
   value:=match[1]
   if strings.HasPrefix(value,"/"){value=origin+value}
   if canonical,ok:=safeDiscoveryPath(origin,value);ok{seen[canonical]=true}
   if len(seen)>=limit{break}
  }
 }
 out:=make([]string,0,len(seen))
 for v:=range seen{out=append(out,v)}
 sort.Strings(out)
 if len(out)>limit{out=out[:limit]}
 return out
}
