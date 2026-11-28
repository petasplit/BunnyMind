// Package bunnypassive queries public certificate transparency records.
// It never resolves or connects to a discovered target host.
package bunnypassive

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "net/url"
 "regexp"
 "sort"
 "strings"
 "time"

 "golang.org/x/net/publicsuffix"
 "github.com/enowdev/antares/internal/bunnynet"
)

var domainRE=regexp.MustCompile(`^[a-z0-9-]+(?:[.][a-z0-9-]+)+$`)
var altTLDRE=regexp.MustCompile(`\((?:[a-z]{2,8}\|){1,8}[a-z]{2,8}\)`)
type Result struct {
 Domain string `json:"domain"`
 Source string `json:"source"`
 QueriedUTC string `json:"queried_utc"`
 Status string `json:"status"`
 RawSHA256 string `json:"raw_sha256,omitempty"`
 Truncated bool `json:"truncated"`
 Candidates []string `json:"candidates"`
 Note string `json:"note"`
}
func ValidDomain(input string)(string,error){
 host:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(input)),".")
 if len(host)>170||!domainRE.MatchString(host)||net.ParseIP(host)!=nil||
  strings.Contains(host,"..")||strings.HasPrefix(host,"localhost") {
  return "",errors.New("passive search requires a valid DNS name, not an IP or localhost")
 }
 registered,err:=publicsuffix.EffectiveTLDPlusOne(host)
 if err!=nil||registered!=host{return "",errors.New("passive domain must be a registrable root, not an arbitrary host")}
 return host,nil
}
// RootsForProgram returns a few registrable domains appearing in program
// scope entries. Wildcard targets are only public CT search seeds: never a
// grant to actively contact newly discovered subdomains.
func RootsForProgram(entries []string)[]string {
 roots:=[]string{}
 seen:=map[string]bool{}
 for _,entry:=range entries{
  first:=strings.TrimSpace(strings.Fields(entry)[0])
  if u,err:=url.Parse(first);err==nil&&u.Scheme!="" {first=u.Hostname()}
  first=strings.TrimPrefix(first,"*.")
  variants:=[]string{first}
  if part:=altTLDRE.FindString(first);part!="" {
   variants=nil
   inner:=strings.Trim(part,"()")
   for _,tld:=range strings.Split(inner,"|"){
    variants=append(variants,strings.Replace(first,part,tld,1))
   }
  }
  for _,candidate:=range variants{
   if !domainRE.MatchString(candidate){continue}
   registered,err:=publicsuffix.EffectiveTLDPlusOne(candidate)
   if err!=nil{continue}
   if valid,err:=ValidDomain(registered);err==nil&&!seen[valid]{
    seen[valid]=true
    roots=append(roots,valid)
   }
  }
 }
 sort.Strings(roots)
 if len(roots)>5{roots=roots[:5]}
 return roots
}
func FilterCTNames(domain string,raw []byte,max int)([]string,error){
 approved,err:=ValidDomain(domain)
 if err!=nil{return nil,err}
 if max<1||max>250{return nil,errors.New("candidate limit must be 1..250")}
 var records []struct{NameValue string `json:"name_value"`}
 if err:=json.Unmarshal(raw,&records);err!=nil{return nil,errors.New("CT provider did not return a complete JSON array")}
 seen:=map[string]bool{}
 for _,row:=range records{
  for _,item:=range strings.Split(row.NameValue,"\n"){
   host:=strings.ToLower(strings.TrimPrefix(strings.TrimSpace(item),"*."))
   if !domainRE.MatchString(host){continue}
   if host==approved||strings.HasSuffix(host,"."+approved) {
    seen[host]=true
   }
  }
 }
 names:=make([]string,0,len(seen))
 for host:=range seen{names=append(names,host)}
 sort.Strings(names)
 if len(names)>max{names=names[:max]}
 return names,nil
}
func Query(ctx context.Context,domain string)(Result,error){
 domain,err:=ValidDomain(domain)
 if err!=nil{return Result{},err}
 reader,err:=bunnynet.New(bunnynet.Policy{Origins:[]string{"https://crt.sh"}})
 if err!=nil{return Result{},err}
 values:=url.Values{"q":{"%."+domain},"output":{"json"}}
 endpoint:="https://crt.sh/?"+values.Encode()
 meta,raw,err:=reader.ReadDocument(ctx,endpoint,"BunnyMind-PassiveCT/0.33 (public certificate records)",512*1024)
 if err!=nil{return Result{},fmt.Errorf("public CT query unavailable: %w",err)}
 out:=Result{Domain:domain,Source:"crt.sh",QueriedUTC:time.Now().UTC().Format(time.RFC3339Nano),
  Status:"incomplete",RawSHA256:meta.BodySHA256,Truncated:meta.Truncated,
  Candidates:[]string{},Note:"Passive certificate names are unverified candidates. No discovered host has been contacted or automatically authorized for assessment."}
 if meta.Status!=200||meta.Truncated{
  out.Note=fmt.Sprintf("CT data incomplete (HTTP %d, truncated=%t); no exhaustive discovery claimed",meta.Status,meta.Truncated)
  return out,nil
 }
 names,err:=FilterCTNames(domain,raw,100)
 if err!=nil{return out,nil}
 out.Candidates=names
 out.Status="public_ct_observations"
 return out,nil
}
