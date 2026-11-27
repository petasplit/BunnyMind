package bunnybrowserflow

import (
 "errors"
 "net/url"
 "regexp"
 "strings"
 "time"

 "github.com/emersion/go-imap"
)

// Only links in an explicitly approved HTTPS origin and a declared endpoint
// prefix may be used. Token-bearing URLs never enter agent-facing output.
var magicURLPattern=regexp.MustCompile("https://[^\\s<>\"']+")

func verifiedEnvelope(message *imap.Message,sender,recipient string,since time.Time) bool {
 if message==nil||message.Envelope==nil||message.Envelope.Date.Before(since.Add(-10*time.Second)){return false}
 fromOK,toOK:=false,false
 for _,addr:=range message.Envelope.From{
  if addr!=nil&&strings.EqualFold(addr.Address(),sender){fromOK=true}
 }
 for _,addr:=range message.Envelope.To{
  if addr!=nil&&strings.EqualFold(addr.Address(),recipient){toOK=true}
 }
 return fromOK&&toOK
}
func magicLinkAllowed(raw string,allow map[string]bool,prefixes []string)bool{
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.Scheme!="https"||u.User!=nil||u.Opaque!=""||
  u.Hostname()==""||(u.Port()!=""&&u.Port()!="443"){return false}
 origin,err:=strictOrigin("https://"+u.Host)
 if err!=nil||!allow[origin]{return false}
 if len(prefixes)==0{return false}
 path:=u.EscapedPath()
 if path==""{path="/"}
 // Reject encoded traversal before any credential-bearing GET occurs.
 if strings.Contains(path,"%2e")||strings.Contains(path,"%2E")||
 strings.Contains(path,"%2f")||strings.Contains(path,"%2F")||
 strings.Contains(path,"%5c")||strings.Contains(path,"%5C")||
 strings.Contains(path,"..")||strings.Contains(path,"\\"){return false}
 for _,prefix:=range prefixes{
  if !safePath(prefix){continue}
  if path==prefix||strings.HasPrefix(path,strings.TrimRight(prefix,"/")+"/"){return true}
 }
 return false
}
func extractVerifiedMagicLink(body,sender,recipient string,message *imap.Message,
 since time.Time,allow map[string]bool,prefixes []string)(string,error){
 if !verifiedEnvelope(message,sender,recipient,since){return "",errors.New("untrusted sender, recipient or stale message")}
 matches:=magicURLPattern.FindAllString(body,16)
 seen:=map[string]bool{}
 for _,raw:=range matches{
  if len(raw)>2048{continue}
  raw=strings.TrimRight(raw,".,;)]}!")
  if magicLinkAllowed(raw,allow,prefixes){seen[raw]=true}
 }
 if len(seen)!=1{return "",errors.New("missing or ambiguous approved magic link")}
 for link:=range seen{return link,nil}
 return "",errors.New("no approved magic link")
}
