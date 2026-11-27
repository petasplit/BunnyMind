package browser

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "net/url"
 "strconv"
 "strings"
 "sync/atomic"
 "time"
)

// externalGate restricts the page layer while the separately configured
// bunnyegress proxy pins outbound TLS tunnels to validated public IPs.
// This is defense-in-depth, not an operating-system firewall.
type externalGate struct{
 allowed map[string]bool
 postPaths map[string]bool
 max int64
 calls atomic.Int64
 blocked atomic.Int64
}
func canonicalHTTPSOrigin(raw string)(string,error){
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.Scheme!="https"||u.Hostname()==""||u.User!=nil||
 u.Opaque!=""||u.RawQuery!=""||u.Fragment!=""||
 (u.Path!=""&&u.Path!="/")||(u.Port()!=""&&u.Port()!="443"){
  return "",errors.New("external browser origins must be HTTPS with default port 443")
 }
 if strings.HasSuffix(u.Hostname(),".")||strings.Contains(u.Hostname(),"%"){return "",errors.New("invalid HTTPS origin")}
 return "https://"+strings.ToLower(u.Hostname()),nil
}
func validateExternalPostPath(path string)bool{
 if len(path)<1||len(path)>256||!strings.HasPrefix(path,"/")||
 strings.HasPrefix(path,"//")||strings.ContainsAny(path,"?#\\\r\n")||
 strings.Contains(path,"%")||strings.Contains(path,".."){return false}
 return true
}
func newExternalGate(origins,postPaths []string,max int)(*externalGate,error){
 if len(origins)==0||len(origins)>32||max<1||max>1000||len(postPaths)>64{
  return nil,errors.New("external browser requires bounded scope, request budget and POST paths")
 }
 g:=&externalGate{allowed:map[string]bool{},postPaths:map[string]bool{},max:int64(max)}
 for _,s:=range origins{
  o,err:=canonicalHTTPSOrigin(s);if err!=nil{return nil,err}
  g.allowed[o]=true
 }
 for _,path:=range postPaths{
  if !validateExternalPostPath(path){return nil,errors.New("invalid approved POST path")}
  g.postPaths[path]=true
 }
 return g,nil
}
func (g *externalGate) allow(raw,method string)bool{
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||
  u.Scheme!="https"||u.Hostname()==""||u.Fragment!=""||
  !g.allowed["https://"+strings.ToLower(u.Hostname())]||
  (u.Port()!=""&&u.Port()!="443"){return false}
 switch method{
 case "GET","HEAD","OPTIONS":
 case "POST":
  if !g.postPaths[u.EscapedPath()]{return false}
 default:return false
 }
 return g.calls.Add(1)<=g.max
}
func externalProxyAddress(raw string)(string,error){
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.Scheme!="http"||u.User!=nil||
 u.RawQuery!=""||u.Fragment!=""||u.Path!=""||
 u.Hostname()!="127.0.0.1"||u.Port()==""{
  return "",errors.New("external proxy must be an exact local HTTP proxy at 127.0.0.1")
 }
 n,err:=strconv.Atoi(u.Port())
 if err!=nil||n<1||n>65535{return "",errors.New("invalid local proxy port")}
 if ip:=net.ParseIP(u.Hostname());ip==nil||!ip.IsLoopback(){return "",errors.New("proxy must be numeric loopback")}
 return "http://"+u.Host,nil
}
func (s *Session) configureExternalGuard(ctx context.Context,c *conn)error{
 g,err:=newExternalGate(s.opts.ExternalOrigins,s.opts.ExternalPostPaths,s.opts.ExternalMaxRequests)
 if err!=nil{return err}
 if _,err:=externalProxyAddress(s.opts.ExternalProxyURL);err!=nil{return err}
 c.setOnEvent(func(method string,params json.RawMessage,sessionID string){
  if method!="Fetch.requestPaused"{return}
  var event struct{
   RequestID string `json:"requestId"`
   Request struct{
    URL string `json:"url"`
    Method string `json:"method"`
   } `json:"request"`
  }
  if json.Unmarshal(params,&event)!=nil||event.RequestID==""{return}
  cmd:="Fetch.continueRequest"
  arg:=map[string]any{"requestId":event.RequestID}
  if !g.allow(event.Request.URL,event.Request.Method){
   g.blocked.Add(1)
   cmd="Fetch.failRequest"
   arg["errorReason"]="BlockedByClient"
  }
  actionCtx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
  defer cancel()
  _,_=c.send(actionCtx,sessionID,cmd,arg)
 })
 if _,err:=c.send(ctx,s.pageSess,"Fetch.enable",map[string]any{
  "patterns":[]map[string]string{{"urlPattern":"*","requestStage":"Request"}},
 });err!=nil{return fmt.Errorf("cannot activate external browser scope: %w",err)}
 return nil
}
