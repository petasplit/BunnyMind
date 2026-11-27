// Package bunnyegress is a local, deny-by-default TLS CONNECT proxy for
// explicitly approved public HTTPS origins. It pins each outbound connection
// to a DNS answer validated immediately before dialing.
package bunnyegress

import (
 "context"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/netip"
 "net/url"
 "strings"
 "sync"
 "sync/atomic"
 "time"
)

type Resolver func(context.Context,string)([]netip.Addr,error)
type Dialer func(context.Context,string,string)(net.Conn,error)
type Config struct {
 Origins []string
 MaxTunnels int
 Resolve Resolver
 Dial Dialer
}
type Proxy struct {
 allowed map[string]bool
 resolve Resolver
 dial Dialer
 max int64
 tunnels atomic.Int64
 blocked atomic.Int64
 mu sync.Mutex
 active map[net.Conn]bool
 server *http.Server
 listener net.Listener
}
func canonical(raw string)(string,error){
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.Scheme!="https"||u.User!=nil||u.Opaque!=""||
 u.Hostname()==""||u.RawQuery!=""||u.Fragment!=""||
 (u.Path!=""&&u.Path!="/"){return "",errors.New("approved destinations must be HTTPS origins only")}
 if u.Port()!=""&&u.Port()!="443"{return "",errors.New("external HTTPS proxy permits port 443 only")}
 host:=strings.ToLower(u.Hostname())
 if strings.HasSuffix(host,".")||strings.Contains(host,"%"){return "",errors.New("invalid hostname")}
 return net.JoinHostPort(host,"443"),nil
}
func defaultResolve(ctx context.Context,host string)([]netip.Addr,error){
 return net.DefaultResolver.LookupNetIP(ctx,"ip",host)
}
func defaultDial(ctx context.Context,network,address string)(net.Conn,error){
 return (&net.Dialer{Timeout:5*time.Second,KeepAlive:-1}).DialContext(ctx,network,address)
}
func New(c Config)(*Proxy,error){
 if len(c.Origins)==0||len(c.Origins)>32{return nil,errors.New("1..32 approved HTTPS origins required")}
 if c.MaxTunnels<1||c.MaxTunnels>256{return nil,errors.New("proxy tunnel budget must be 1..256")}
 p:=&Proxy{allowed:map[string]bool{},max:int64(c.MaxTunnels),active:map[net.Conn]bool{}}
 for _,origin:=range c.Origins{
  host,err:=canonical(origin);if err!=nil{return nil,err}
  p.allowed[strings.ToLower(host)]=true
 }
 p.resolve=c.Resolve;p.dial=c.Dial
 if p.resolve==nil{p.resolve=defaultResolve}
 if p.dial==nil{p.dial=defaultDial}
 return p,nil
}
// PublicIP rejects special-use, internal, metadata and documentation ranges.
// Used by the trusted IMAP connector to enforce the same public egress checks.
func PublicIP(ip netip.Addr)bool{return !forbidden(ip)}
func forbidden(ip netip.Addr)bool{
 if !ip.IsValid()||ip.Is4In6(){ip=ip.Unmap()}
 if !ip.IsValid()||ip.IsUnspecified()||ip.IsLoopback()||ip.IsPrivate()||
 ip.IsLinkLocalUnicast()||ip.IsLinkLocalMulticast()||ip.IsMulticast()||!ip.IsGlobalUnicast(){
  return true
 }
 // Additional special-use ranges that netip.IsPrivate does not include.
 prefixes:=[]string{
  "0.0.0.0/8","100.64.0.0/10","192.0.0.0/24","192.0.2.0/24",
  "198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4",
  "240.0.0.0/4","2001:db8::/32","2001::/32","2002::/16",
 }
 for _,c:=range prefixes{
  if netip.MustParsePrefix(c).Contains(ip){return true}
 }
 return false
}
func (p *Proxy) allowedAddress(ctx context.Context,authority string)(string,error){
 host,port,err:=net.SplitHostPort(authority)
 if err!=nil||port!="443"{return "",errors.New("CONNECT requires an approved host on port 443")}
 if strings.Contains(host,"%")||strings.HasSuffix(host,".")||
  !p.allowed[strings.ToLower(net.JoinHostPort(host,port))]{
  return "",errors.New("CONNECT destination is not an approved origin")
 }
 var ips []netip.Addr
 if literal,err:=netip.ParseAddr(host);err==nil{
  ips=[]netip.Addr{literal}
 }else{
  lookupCtx,cancel:=context.WithTimeout(ctx,4*time.Second)
  defer cancel()
  ips,err=p.resolve(lookupCtx,host)
  if err!=nil{return "",errors.New("approved target DNS lookup failed")}
 }
 if len(ips)==0{return "",errors.New("approved origin has no DNS addresses")}
 // All answers must be safe, not just the address selected for dialing.
 for _,ip:=range ips{
  if forbidden(ip){return "",errors.New("DNS returned a blocked or mixed destination address")}
 }
 return net.JoinHostPort(ips[0].Unmap().String(),port),nil
}
func (p *Proxy) track(c net.Conn,add bool){
 p.mu.Lock();defer p.mu.Unlock()
 if add{p.active[c]=true}else{delete(p.active,c)}
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter,r *http.Request){
 if r.Method!="CONNECT"{
  p.blocked.Add(1)
  http.Error(w,"CONNECT only",http.StatusForbidden)
  return
 }
 address,err:=p.allowedAddress(r.Context(),r.Host)
 if err!=nil{p.blocked.Add(1);http.Error(w,"destination denied",http.StatusForbidden);return}
 if p.tunnels.Add(1)>p.max{
  p.blocked.Add(1);http.Error(w,"tunnel budget exhausted",http.StatusTooManyRequests);return
 }
 ctx,cancel:=context.WithTimeout(r.Context(),8*time.Second)
 remote,err:=p.dial(ctx,"tcp",address)
 cancel()
 if err!=nil{p.blocked.Add(1);http.Error(w,"connection unavailable",http.StatusBadGateway);return}
 hijack,ok:=w.(http.Hijacker)
 if !ok{remote.Close();http.Error(w,"proxy hijack unavailable",500);return}
 client,buf,err:=hijack.Hijack()
 if err!=nil{remote.Close();return}
 p.track(client,true);p.track(remote,true)
 defer func(){client.Close();remote.Close();p.track(client,false);p.track(remote,false)}()
 if _,err:=io.WriteString(client,"HTTP/1.1 200 Connection Established\r\n\r\n");err!=nil{return}
 // Preserve any bytes Chrome pipelined immediately after CONNECT.
 if n:=buf.Reader.Buffered();n>0{
  if _,err:=io.CopyN(remote,buf.Reader,int64(n));err!=nil{return}
 }
 done:=make(chan struct{},1)
 go func(){_,_=io.Copy(remote,client);if tcp,ok:=remote.(*net.TCPConn);ok{_ = tcp.CloseWrite()};done<-struct{}{}}()
 _,_=io.Copy(client,remote)
 client.Close()
 <-done
}
func (p *Proxy) Start()(string,error){
 p.mu.Lock()
 if p.listener!=nil{p.mu.Unlock();return "",errors.New("proxy already started")}
 p.mu.Unlock()
 listener,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil{return "",err}
 p.mu.Lock()
 p.listener=listener
 p.server=&http.Server{Handler:p,ReadHeaderTimeout:5*time.Second,IdleTimeout:15*time.Second}
 server:=p.server
 p.mu.Unlock()
 go func(){_ = server.Serve(listener)}()
 return "http://"+listener.Addr().String(),nil
}
func (p *Proxy) Close(){
 p.mu.Lock()
 listener,server:=p.listener,p.server
 p.listener=nil;p.server=nil
 var active []net.Conn
 for c:=range p.active{active=append(active,c)}
 p.mu.Unlock()
 if listener!=nil{_ = listener.Close()}
 if server!=nil{_ = server.Close()}
 for _,c:=range active{_ = c.Close()}
}
func (p *Proxy) Stats() (tunnels,blocked int64){return p.tunnels.Load(),p.blocked.Load()}
func (p *Proxy) String()string{return fmt.Sprintf("restricted HTTPS proxy (%d approved origins)",len(p.allowed))}
