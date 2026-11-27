package bunnyegress

import (
 "bufio"
 "context"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "net/netip"
 "strings"
 "testing"
 "time"
)

func TestExplicitHTTPSOriginsOnly(t *testing.T){
 for _,target:=range []string{"http://example.com","https://example.com/path",
  "https://user:pass@example.com","https://example.com:8443",
  "https://example.com?a=1","https://example.com.","https://example.com#fragment"}{
  if _,err:=New(Config{Origins:[]string{target},MaxTunnels:2});err==nil{
   t.Fatalf("allowed unapproved origin %q",target)
  }
 }
 if _,err:=New(Config{Origins:[]string{"https://example.com"},MaxTunnels:2});err!=nil{t.Fatal(err)}
}
func TestDenyPrivateAndSpecialUseIPs(t *testing.T){
 for _,raw:=range []string{"127.0.0.1","10.1.2.3","192.168.0.1","172.16.0.1",
 "169.254.169.254","100.64.0.1","192.0.2.1","198.51.100.4","203.0.113.10",
 "198.18.0.1","::1","fc00::1","fe80::1","2001:db8::1"}{
  if !forbidden(netip.MustParseAddr(raw)){t.Fatalf("special IP permitted: %s",raw)}
 }
 for _,raw:=range []string{"8.8.8.8","1.1.1.1","2606:4700:4700::1111"}{
  if forbidden(netip.MustParseAddr(raw)){t.Fatalf("public IP blocked: %s",raw)}
 }
}
func TestRejectMixedDNSAnswersBeforeConnecting(t *testing.T){
 called:=0
 p,err:=New(Config{
  Origins:[]string{"https://approved.example"},MaxTunnels:2,
  Resolve:func(context.Context,string)([]netip.Addr,error){
   return []netip.Addr{netip.MustParseAddr("8.8.8.8"),netip.MustParseAddr("127.0.0.1")},nil
  },
  Dial:func(context.Context,string,string)(net.Conn,error){
   called++;return nil,nil
  },
 })
 if err!=nil{t.Fatal(err)}
 if _,err:=p.allowedAddress(context.Background(),"approved.example:443");err==nil{t.Fatal("accepted mixed DNS")}
 if called!=0{t.Fatal("dialed before validating DNS")}
 if _,err:=p.allowedAddress(context.Background(),"not-approved.example:443");err==nil{t.Fatal("accepted offscope host")}
 if _,err:=p.allowedAddress(context.Background(),"approved.example:80");err==nil{t.Fatal("accepted port 80")}
}
func TestProxyNeverForwardsOrdinaryHTTP(t *testing.T){
 p,_:=New(Config{Origins:[]string{"https://approved.example"},MaxTunnels:2})
 recorder:=httptest.NewRecorder()
 p.ServeHTTP(recorder,httptest.NewRequest("GET","http://approved.example/secrets",nil))
 if recorder.Code!=http.StatusForbidden{t.Fatalf("unexpected response %d",recorder.Code)}
 if _,blocked:=p.Stats();blocked!=1{t.Fatalf("blocked count %d",blocked)}
}
func TestPinnedTunnelUsesValidatedIP(t *testing.T){
 gotAddress:=""
 p,err:=New(Config{
  Origins:[]string{"https://approved.example"},MaxTunnels:1,
  Resolve:func(ctx context.Context,host string)([]netip.Addr,error){
   if host!="approved.example"{t.Errorf("bad DNS hostname %s",host)}
   return []netip.Addr{netip.MustParseAddr("1.1.1.1")},nil
  },
  Dial:func(_ context.Context,network,address string)(net.Conn,error){
   gotAddress=address
   a,b:=net.Pipe()
   go func(){
    defer b.Close()
    buf:=make([]byte,4)
    if _,err:=io.ReadFull(b,buf);err==nil&&string(buf)=="ping"{
     _,_=b.Write([]byte("pong"))
    }
   }()
   return a,nil
  },
 })
 if err!=nil{t.Fatal(err)}
 address,err:=p.Start()
 if err!=nil{t.Fatal(err)}
 defer p.Close()
 conn,err:=net.DialTimeout("tcp",strings.TrimPrefix(address,"http://"),3*time.Second)
 if err!=nil{t.Fatal(err)}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(4*time.Second))
 _,_=conn.Write([]byte("CONNECT approved.example:443 HTTP/1.1\r\nHost: approved.example:443\r\n\r\n"))
 reader:=bufio.NewReader(conn)
 status,err:=reader.ReadString('\n')
 if err!=nil||!strings.Contains(status,"200"){t.Fatalf("CONNECT failed %q %v",status,err)}
 for {
  line,e:=reader.ReadString('\n')
  if e!=nil{t.Fatal(e)}
  if line=="\r\n"{break}
 }
 if _,err:=conn.Write([]byte("ping"));err!=nil{t.Fatal(err)}
 got:=make([]byte,4)
 if _,err:=io.ReadFull(reader,got);err!=nil||string(got)!="pong"{t.Fatalf("unexpected tunnel %q %v",got,err)}
 if gotAddress!="1.1.1.1:443"{t.Fatalf("DNS pin not used: %s",gotAddress)}
 if n,_:=p.Stats();n!=1{t.Fatalf("unexpected tunnel count %d",n)}
}
