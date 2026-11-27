package browser

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "net/url"
 "strings"
 "sync/atomic"
 "time"
)

// loopbackGate is the additional CDP request interceptor used ONLY by
// disposable, operator-controlled local browser authentication fixtures.
// A public-hostname browser sandbox requires a separate DNS/IP-pinned egress
// boundary and is intentionally not provided by this lab-only gate.
type loopbackGate struct {
 origin string
 calls atomic.Int64
 blocked atomic.Int64
}
const maxLoopbackRequests=64

func parseLoopbackOrigin(raw string)(string,error){
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.Scheme!="http"||u.Hostname()==""||u.Port()==""||
  u.Opaque!=""||u.User!=nil||u.Path!=""||u.RawQuery!=""||u.Fragment!=""{
  return "",errors.New("browser fixture requires a numeric-loopback HTTP origin with an explicit port")
 }
 ip:=net.ParseIP(u.Hostname())
 if ip==nil||!ip.IsLoopback(){return "",errors.New("only numeric loopback fixture origins are allowed")}
 return "http://"+u.Host,nil
}
func (g *loopbackGate) allow(raw,method string)bool {
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||u.Fragment!=""||
  u.Scheme!="http"||"http://"+u.Host!=g.origin{return false}
 switch strings.ToUpper(method){
 case "GET","HEAD","OPTIONS","POST":
 default:return false
 }
 return g.calls.Add(1)<=maxLoopbackRequests
}
func (s *Session) configureLoopbackGuard(ctx context.Context,c *conn)error{
 // This method is invoked during Start before user navigation, after CDP has
 // attached to the blank page. It does not change existing normal sessions.
 origin,err:=parseLoopbackOrigin(s.opts.LoopbackOrigin)
 if err!=nil{return err}
 if s.opts.RemoteURL!=""||s.opts.Proxy!=""||s.opts.Stealth||s.opts.UserDataDir!=""{
  return errors.New("isolated fixture must launch its own clean browser without proxy, remote debugger, stealth or persistent profile")
 }
 gate:=&loopbackGate{origin:origin}
 c.setOnEvent(func(method string,params json.RawMessage,sessionID string){
  if method!="Fetch.requestPaused"{return}
  var paused struct{
   RequestID string `json:"requestId"`
   Request struct{
    URL string `json:"url"`
    Method string `json:"method"`
   } `json:"request"`
  }
  if err:=json.Unmarshal(params,&paused);err!=nil||paused.RequestID==""{return}
  operation:="Fetch.continueRequest"
  arguments:=map[string]any{"requestId":paused.RequestID}
  if !gate.allow(paused.Request.URL,paused.Request.Method){
   gate.blocked.Add(1)
   operation="Fetch.failRequest"
   arguments["errorReason"]="BlockedByClient"
  }
  callCtx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
  defer cancel()
  _,_ = c.send(callCtx,sessionID,operation,arguments)
 })
 _,err=c.send(ctx,s.pageSess,"Fetch.enable",map[string]any{
  "patterns":[]map[string]string{{"urlPattern":"*","requestStage":"Request"}},
 })
 if err!=nil{return fmt.Errorf("cannot activate page request gate: %w",err)}
 return nil
}
