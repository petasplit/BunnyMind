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
 "sync"
 "time"
)

// externalGate restricts the page layer while the separately configured
// bunnyegress proxy pins outbound TLS tunnels to validated public IPs.
// This is defense-in-depth, not an operating-system firewall.
type externalGate struct{
 allowed map[string]bool
 postPaths map[string]bool
 max int64
 minInterval time.Duration
 pacingMu sync.Mutex
 next time.Time
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
func newExternalGate(origins,postPaths []string,max,minIntervalMS int)(*externalGate,error){
 if len(origins)==0||len(origins)>32||max<1||max>1000||minIntervalMS<0||minIntervalMS>5000||len(postPaths)>64{
  return nil,errors.New("external browser requires bounded scope, request budget and POST paths")
 }
 g:=&externalGate{allowed:map[string]bool{},postPaths:map[string]bool{},max:int64(max),minInterval:time.Duration(minIntervalMS)*time.Millisecond}
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
 if g.calls.Add(1)>g.max{return false}
 g.pacingMu.Lock()
 if delay:=time.Until(g.next);delay>0{time.Sleep(delay)}
 g.next=time.Now().Add(g.minInterval)
 g.pacingMu.Unlock()
 return true
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
 g,err:=newExternalGate(s.opts.ExternalOrigins,s.opts.ExternalPostPaths,s.opts.ExternalMaxRequests,s.opts.ExternalMinIntervalMS)
 if err!=nil{return err}
 if _,err:=externalProxyAddress(s.opts.ExternalProxyURL);err!=nil{return err}
 c.setOnEvent(func(method string,params json.RawMessage,sessionID string){
  switch method{
  case "Target.attachedToTarget":
   var attached struct {
    SessionID string `json:"sessionId"`
    TargetInfo struct{
     TargetID string `json:"targetId"`
     Type string `json:"type"`
     URL string `json:"url"`
    } `json:"targetInfo"`
   }
   if json.Unmarshal(params,&attached)==nil&&attached.TargetInfo.Type=="page"{
    s.acceptPopup(c,g,attached.SessionID,attached.TargetInfo.TargetID,attached.TargetInfo.URL)
   }
   return
  case "Target.detachedFromTarget":
   var detached struct{SessionID string `json:"sessionId"`}
   if json.Unmarshal(params,&detached)==nil&&detached.SessionID!=""{
    s.removePopup(detached.SessionID)
   }
   return
  case "Fetch.requestPaused":
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
  }
 })
 if _,err:=c.send(ctx,s.pageSess,"Fetch.enable",map[string]any{
  "patterns":[]map[string]string{{"urlPattern":"*","requestStage":"Request"}},
 });err!=nil{return fmt.Errorf("cannot activate external browser scope: %w",err)}
 // New popup pages attach frozen; each receives the same request gate before
 // navigating. The DNS-pinned local proxy also rejects offscope destinations.
 if _,err:=c.send(ctx,"","Target.setAutoAttach",map[string]any{
  "autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true,
 });err!=nil{return fmt.Errorf("cannot guard new browser tabs: %w",err)}
 return nil
}
