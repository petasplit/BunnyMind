// Package bunnynet provides a conservative, read-only HTTP client for
// explicitly approved origins. It does not proxy or contain other tools.
package bunnynet

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "strings"
 "time"
 "unicode/utf8"
)

const MaxBody=65536
type Policy struct {
 Origins []string
 PrivateCIDRs []string
}
type Result struct {
 Status int `json:"status"`
 Origin string `json:"origin"`
 ContentType string `json:"content_type,omitempty"`
 BodySHA256 string `json:"body_sha256"`
 BytesRead int `json:"bytes_read"`
 Truncated bool `json:"truncated"`
 RedirectBlocked bool `json:"redirect_blocked"`
 Preview string `json:"preview,omitempty"`
}
type Reader struct{
 allowed map[string]bool
 networks []*net.IPNet
}
func New(p Policy)(*Reader,error){
 if len(p.Origins)==0||len(p.Origins)>100{return nil,errors.New("1..100 explicitly approved origins required")}
 r:=&Reader{allowed:map[string]bool{}}
 for _,raw:=range p.Origins{
  u,err:=url.Parse(raw)
  if err!=nil||u==nil||u.Opaque!=""||u.User!=nil||
   (u.Scheme!="http"&&u.Scheme!="https")||u.Hostname()==""||
   (u.Path!=""&&u.Path!="/")||u.RawQuery!=""||u.Fragment!=""{
   return nil,fmt.Errorf("invalid origin %q",raw)
  }
  r.allowed[strings.ToLower(u.Scheme+"://"+u.Host)]=true
 }
 if len(p.PrivateCIDRs)>16{return nil,errors.New("too many private CIDR exceptions")}
 for _,raw:=range p.PrivateCIDRs{
  _,netblock,err:=net.ParseCIDR(raw)
  if err!=nil{return nil,fmt.Errorf("invalid CIDR %q",raw)}
  ones,_:=netblock.Mask.Size()
  if ones==0{return nil,errors.New("default-route private exception forbidden")}
  r.networks=append(r.networks,netblock)
 }
 return r,nil
}
func (r *Reader) allowedIP(ip net.IP, targetLiteral net.IP) bool{
 if ip==nil||ip.IsUnspecified()||ip.IsMulticast(){return false}
 // An explicit IP literal is authorized ONLY for that exact address.
 if targetLiteral!=nil{return targetLiteral.Equal(ip)}
 if ip.IsLoopback()||ip.IsPrivate()||ip.IsLinkLocalUnicast()||ip.IsLinkLocalMulticast()||!ip.IsGlobalUnicast(){
  for _,cidr:=range r.networks{if cidr.Contains(ip){return true}}
  return false
 }
 return true
}
func (r *Reader) allowedTarget(raw string)(*url.URL,string,error){
 u,err:=url.Parse(strings.TrimSpace(raw))
 if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||
  (u.Scheme!="http"&&u.Scheme!="https")||u.Hostname()==""||u.Fragment!=""{
  return nil,"",errors.New("invalid HTTP(S) destination")
 }
 origin:=strings.ToLower(u.Scheme+"://"+u.Host)
 if !r.allowed[origin]{return nil,"",errors.New("destination outside approved origins")}
 return u,origin,nil
}
// Read follows NO redirects. Each connection is dialed directly to an IP
// validated after DNS lookup, without an environment proxy. It only permits
// GET/HEAD; each call opens a fresh transport without pooled DNS state.
func (r *Reader) Read(ctx context.Context,rawURL,method string,previewBytes int)(Result,error){
 if previewBytes<0||previewBytes>8192{return Result{},errors.New("preview_bytes must be 0..8192")}
 result,payload,err:=r.readPayload(ctx,rawURL,method,MaxBody,"BunnyMind-ScopedRead/0.5 (authorized testing)")
 if err!=nil{return Result{},err}
 if previewBytes>len(payload){previewBytes=len(payload)}
 if previewBytes>0{
  result.Preview=strings.ToValidUTF8(string(payload[:previewBytes]),"�")
  if !utf8.ValidString(result.Preview){result.Preview=""}
 }
 return result,nil
}
// ReadDocument returns bounded page bytes for a trusted on-disk parser.
// The caller must enforce the same preapproved scope as any other request;
// this method never follows a redirect, accesses cookies, or relaxes DNS policy.
func (r *Reader) ReadDocument(ctx context.Context,rawURL,agent string,maxBody int)(Result,[]byte,error){
 if maxBody<1||maxBody>512*1024{return Result{},nil,errors.New("document limit must be 1..512 KiB")}
 if len(agent)<5||len(agent)>160||strings.ContainsAny(agent,"\\r\\n"){return Result{},nil,errors.New("invalid user agent")}
 return r.readPayload(ctx,rawURL,"GET",maxBody,agent)
}
func (r *Reader) readPayload(ctx context.Context,rawURL,method string,maxBody int,userAgent string)(Result,[]byte,error){
 u,origin,err:=r.allowedTarget(rawURL)
 if err!=nil{return Result{},nil,err}
 method=strings.ToUpper(strings.TrimSpace(method))
 if method==""{method="GET"}
 if method!="GET"&&method!="HEAD"{return Result{},nil,errors.New("scoped reader permits GET/HEAD only")}
 targetLiteral:=net.ParseIP(u.Hostname())
 d:=&net.Dialer{Timeout:4*time.Second}
 transport:=&http.Transport{
  Proxy:nil,
  DisableKeepAlives:true,
  MaxConnsPerHost:1,
  TLSHandshakeTimeout:5*time.Second,
  ResponseHeaderTimeout:7*time.Second,
  DialContext:func(c context.Context,network,address string)(net.Conn,error){
   host,port,err:=net.SplitHostPort(address)
   if err!=nil{return nil,err}
   if !strings.EqualFold(strings.TrimSuffix(host,"."),strings.TrimSuffix(u.Hostname(),".")){
    return nil,errors.New("transport attempted a different host")
   }
   var ips []net.IP
   if literal:=net.ParseIP(host);literal!=nil{ips=[]net.IP{literal}
   }else{
    records,err:=net.DefaultResolver.LookupIPAddr(c,host)
    if err!=nil{return nil,err}
    for _,rec:=range records{ips=append(ips,rec.IP)}
   }
   if len(ips)==0{return nil,errors.New("host has no DNS addresses")}
   // Reject mixed public/private answers rather than selecting a good one
   // while silently accepting a possible DNS rebinding target.
   for _,ip:=range ips{
    if !r.allowedIP(ip,targetLiteral){return nil,errors.New("destination IP outside approved address policy")}
   }
   // Dial the reviewed address, never the original hostname again.
   return d.DialContext(c,network,net.JoinHostPort(ips[0].String(),port))
  },
 }
 defer transport.CloseIdleConnections()
 client:=&http.Client{
  Timeout:12*time.Second,
  Transport:transport,
  CheckRedirect:func(req *http.Request,via []*http.Request)error{
   return http.ErrUseLastResponse
  },
 }
 request,err:=http.NewRequestWithContext(ctx,method,u.String(),nil)
 if err!=nil{return Result{},nil,err}
 request.Header.Set("User-Agent",userAgent)
 response,err:=client.Do(request)
 if err!=nil{return Result{},nil,err}
 defer response.Body.Close()
 payload,err:=io.ReadAll(io.LimitReader(response.Body,int64(maxBody)+1))
 if err!=nil{return Result{},nil,err}
 truncated:=len(payload)>maxBody
 if truncated{payload=payload[:maxBody]}
 hash:=sha256.Sum256(payload)
 output:=Result{
  Status:response.StatusCode,Origin:origin,ContentType:response.Header.Get("Content-Type"),
  BodySHA256:hex.EncodeToString(hash[:]),BytesRead:len(payload),
  Truncated:truncated,RedirectBlocked:response.StatusCode>=300&&response.StatusCode<400&&response.Header.Get("Location")!="",
 }
 return output,payload,nil
}
