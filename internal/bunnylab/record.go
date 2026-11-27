// Package bunnylab captures HTTP observations from explicitly configured
// loopback-only training services, then signs metadata with a separate key.
// It does not run a security scanner, exploit or cloud-based agent.
package bunnylab

import (
 "context"
 "crypto/ed25519"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnyreceipt"
)

const MaxBody=65536
const MaxProbes=32

type Probe struct {
 SampleID string `json:"sample_id"`
 Kind string `json:"kind"`
 Path string `json:"path"`
}
type Plan struct {
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 CaseID string `json:"case_id"`
 Origin string `json:"origin"`
 Marker string `json:"marker"`
 Probes []Probe `json:"probes"`
}
func loopbackOrigin(raw string)(*url.URL,error){
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.Opaque!=""||u.User!=nil||
 (u.Scheme!="http"&&u.Scheme!="https")||u.Hostname()==""||
 (u.Path!=""&&u.Path!="/")||u.RawQuery!=""||u.Fragment!=""{
  return nil,errors.New("absolute HTTP(S) origin without credentials or path required")
 }
 address:=net.ParseIP(u.Hostname())
 if address==nil||!address.IsLoopback(){return nil,errors.New("recorder accepts only numeric loopback IP origins")}
 port:=u.Port()
 n,e:=strconv.Atoi(port)
 if e!=nil||n<1||n>65535{return nil,errors.New("explicit TCP port 1..65535 required")}
 return u,nil
}
func validPath(raw string)error{
 if !strings.HasPrefix(raw,"/")||strings.HasPrefix(raw,"//")||
 strings.ContainsAny(raw," \t\r\n")||len(raw)>2048{
  return errors.New("probe path must be a bounded, absolute-path relative reference")
 }
 u,err:=url.ParseRequestURI(raw)
 if err!=nil||u==nil||u.IsAbs()||u.Host!=""||u.Fragment!=""{
  return errors.New("invalid probe path")
 }
 return nil
}
func Validate(plan Plan)error{
 if _,err:=loopbackOrigin(plan.Origin);err!=nil{return err}
 if len(plan.Marker)<6||len(plan.Marker)>128||strings.ContainsAny(plan.Marker,"\r\n"){
  return errors.New("marker must be 6..128 characters without line breaks")
 }
 if len(plan.Probes)<4||len(plan.Probes)>MaxProbes{
  return fmt.Errorf("plan requires 4..%d probes",MaxProbes)
 }
 first:=bunnyreceipt.Observation{
  Version:1,EngagementID:plan.EngagementID,RunID:plan.RunID,CaseID:plan.CaseID,
  SampleID:"validation",Kind:"positive",Method:"GET",Origin:plan.Origin,
  RequestSHA256:bunnyreceipt.Dig("sample"),ResponseSHA256:bunnyreceipt.Dig("sample"),
  MarkerSHA256:bunnyreceipt.Dig(plan.Marker),ResponseStatus:200,RecordedAt:time.Now().UTC().Format(time.RFC3339Nano),
 }
 if err:=bunnyreceipt.ValidObservation(first);err!=nil{return fmt.Errorf("invalid lab run metadata: %w",err)}
 seen:=map[string]bool{}
 positives,controls:=0,0
 for _,p:=range plan.Probes{
  first.SampleID=p.SampleID;first.Kind=p.Kind
  if err:=bunnyreceipt.ValidObservation(first);err!=nil{return fmt.Errorf("invalid probe metadata: %w",err)}
  if seen[p.SampleID]{return errors.New("duplicate probe sample IDs")}
  seen[p.SampleID]=true
  if err:=validPath(p.Path);err!=nil{return err}
  if p.Kind=="positive"{positives++}else{controls++}
 }
 if positives<2||controls<2{return errors.New("plan needs at least two positives and two negative controls")}
 return nil
}
// Capture runs strictly bounded GET requests to the specified numeric loopback
// origin. Redirects, large bodies and all non-loopback destinations fail.
// Only signed metadata is returned; response bodies remain in memory.
func Capture(ctx context.Context,plan Plan,private ed25519.PrivateKey)(bunnyreceipt.Bundle,error){
 if len(private)!=ed25519.PrivateKeySize{return bunnyreceipt.Bundle{},errors.New("invalid Ed25519 private key")}
 if err:=Validate(plan);err!=nil{return bunnyreceipt.Bundle{},err}
 u,_:=loopbackOrigin(plan.Origin)
 address:=net.ParseIP(u.Hostname())
 host,port:=u.Hostname(),u.Port()
 dialer:=&net.Dialer{Timeout:3*time.Second}
 transport:=&http.Transport{
  Proxy:nil,DisableKeepAlives:true,MaxConnsPerHost:1,
  TLSHandshakeTimeout:3*time.Second,ResponseHeaderTimeout:4*time.Second,
  DialContext:func(c context.Context,network,destination string)(net.Conn,error){
   actualHost,actualPort,err:=net.SplitHostPort(destination)
   if err!=nil{return nil,err}
   actualIP:=net.ParseIP(actualHost)
   if actualIP==nil||!actualIP.Equal(address)||actualPort!=port{
    return nil,errors.New("transport attempted to leave approved loopback destination")
   }
   return dialer.DialContext(c,"tcp",net.JoinHostPort(host,port))
  },
 }
 defer transport.CloseIdleConnections()
 client:=&http.Client{
  Transport:transport,Timeout:8*time.Second,
  CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
 }
 result:=bunnyreceipt.Bundle{
  EngagementID:plan.EngagementID,RunID:plan.RunID,CaseID:plan.CaseID,
  Receipts:make([]bunnyreceipt.Signed,0,len(plan.Probes)),
 }
 for _,probe:=range plan.Probes{
  full:=plan.Origin+probe.Path
  request,err:=http.NewRequestWithContext(ctx,"GET",full,nil)
  if err!=nil{return bunnyreceipt.Bundle{},err}
  request.Header.Set("User-Agent","BunnyMind-LocalLab-Recorder/0.11")
  response,err:=client.Do(request)
  if err!=nil{return bunnyreceipt.Bundle{},fmt.Errorf("local probe failed (%s): %w",probe.SampleID,err)}
  payload,readErr:=io.ReadAll(io.LimitReader(response.Body,MaxBody+1))
  closeErr:=response.Body.Close()
  if readErr!=nil||closeErr!=nil{return bunnyreceipt.Bundle{},errors.New("could not read local fixture response")}
  if len(payload)>MaxBody{return bunnyreceipt.Bundle{},errors.New("fixture response exceeded 64KiB limit")}
  if response.StatusCode>=300&&response.StatusCode<400{
   return bunnyreceipt.Bundle{},errors.New("redirect response refused; no location followed")
  }
  decodedPath,_:=url.QueryUnescape(probe.Path)
  reflected:=strings.Contains(probe.Path,plan.Marker)||strings.Contains(decodedPath,plan.Marker)
  obs:=bunnyreceipt.Observation{
   Version:1,EngagementID:plan.EngagementID,RunID:plan.RunID,CaseID:plan.CaseID,
   SampleID:probe.SampleID,Kind:probe.Kind,Method:"GET",Origin:plan.Origin,
   RequestSHA256:bunnyreceipt.Dig("GET\n"+full),
   ResponseSHA256:bunnyreceipt.Dig(string(payload)),
   MarkerSHA256:bunnyreceipt.Dig(plan.Marker),
   ResponseStatus:response.StatusCode,MarkerPresent:strings.Contains(string(payload),plan.Marker),
   MarkerInRequest:reflected,RecordedAt:time.Now().UTC().Format(time.RFC3339Nano),
  }
  receipt,err:=bunnyreceipt.Sign(private,obs)
  if err!=nil{return bunnyreceipt.Bundle{},err}
  result.Receipts=append(result.Receipts,receipt)
 }
 return result,nil
}
