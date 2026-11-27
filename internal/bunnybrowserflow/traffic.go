package bunnybrowserflow

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "net/url"
 "strconv"
 "strings"

 "github.com/enowdev/antares/internal/browser"
)
const MaxTrafficReceipts=256
type TrafficReceipt struct {
 Actor string `json:"actor"`
 Step int `json:"step"`
 Method string `json:"method"`
 Origin string `json:"origin"`
 PathSHA256 string `json:"path_sha256"`
 Status int `json:"status"`
 Outcome string `json:"outcome"`
 ReceiptSHA256 string `json:"receipt_sha256"`
}
// TrafficObserver is an optional browser capability. It never exposes raw
// network bodies, URLs, headers, cookies or credentials to the agent runner.
type TrafficObserver interface {
 CaptureTraffic(context.Context,string,int,map[string]bool)[]TrafficReceipt
}
func redactTraffic(actor string,step int,requests []browser.NetworkRequest,allowed map[string]bool)[]TrafficReceipt{
 out:=[]TrafficReceipt{}
 if !validActor.MatchString(actor)||step<1{return out}
 for _,r:=range requests {
  if len(out)>=MaxTrafficReceipts{break}
  method:=strings.ToUpper(r.Method)
  switch method{case "GET","HEAD","POST","OPTIONS":default:continue}
  u,err:=url.Parse(r.URL)
  if err!=nil||u==nil||u.Hostname()==""||u.User!=nil||u.Opaque!=""{continue}
  origin:=strings.ToLower(u.Scheme+"://"+u.Host)
  if !allowed[origin]{
   if u.Port()=="443"&&u.Scheme=="https"{
    origin="https://"+strings.ToLower(u.Hostname())
   }
  }
  if !allowed[origin]{continue}
  path:=u.EscapedPath()
  if path==""{path="/"}
  fingerprint:=sha256.Sum256([]byte(method+"\n"+origin+"\n"+path))
  status:=0;outcome:="pending"
  if r.Response!=nil{
   status=r.Response.Status
   outcome="responded"
  }else if r.Failed!=""{outcome="failed"}
  digest:=sha256.Sum256([]byte(actor+"\n"+method+"\n"+origin+"\n"+hex.EncodeToString(fingerprint[:])+"\n"+strconv.Itoa(step)+"\n"+strconv.Itoa(status)+"\n"+outcome))
  out=append(out,TrafficReceipt{
   Actor:actor,Step:step,Method:method,Origin:origin,
   PathSHA256:hex.EncodeToString(fingerprint[:]),
   Status:status,Outcome:outcome,ReceiptSHA256:hex.EncodeToString(digest[:]),
  })
 }
 return out
}
func (d *chromeDriver) CaptureTraffic(ctx context.Context,actor string,step int,allowed map[string]bool)[]TrafficReceipt{
 return redactTraffic(actor,step,d.session.DrainNetwork(ctx),allowed)
}
