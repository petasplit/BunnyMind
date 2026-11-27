package bunnynet

import (
 "context"
 "net"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"
)
func local(t *testing.T,handler http.Handler)(*Reader,*httptest.Server){
 t.Helper()
 srv:=httptest.NewServer(handler)
 r,err:=New(Policy{Origins:[]string{srv.URL}})
 if err!=nil{srv.Close();t.Fatal(err)}
 t.Cleanup(srv.Close)
 return r,srv
}
func TestApprovedLoopbackGET(t *testing.T){
 r,s:=local(t,http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){w.WriteHeader(200);_,_=w.Write([]byte("local-proof"))}))
 result,err:=r.Read(context.Background(),s.URL+"/health","GET",64)
 if err!=nil||result.Status!=200||result.Preview!="local-proof"||result.BytesRead!=11{
  t.Fatalf("got=%+v err=%v",result,err)
 }
}
func TestCrossOriginRejectedBeforeDial(t *testing.T){
 r,s:=local(t,http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){w.WriteHeader(200)}))
 if _,err:=r.Read(context.Background(),strings.Replace(s.URL,"127.0.0.1","127.0.0.2",1),"GET",0);err==nil{
  t.Fatal("out-of-scope IP allowed")
 }
}
func TestNoRedirectFollow(t *testing.T){
 var targetHits atomic.Int32
 dest:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){targetHits.Add(1)}))
 defer dest.Close()
 r,s:=local(t,http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){http.Redirect(w,req,dest.URL+"/outside",http.StatusFound)}))
 out,err:=r.Read(context.Background(),s.URL+"/jump","GET",0)
 if err!=nil||out.Status!=302||!out.RedirectBlocked||targetHits.Load()!=0{
  t.Fatalf("redirect escaped out=%+v hits=%d err=%v",out,targetHits.Load(),err)
 }
}
func TestMutatingMethodsRejected(t *testing.T){
 r,s:=local(t,http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){t.Fatal("should not send request")}))
 for _,m:=range []string{"POST","PUT","DELETE","PATCH"}{
  if _,err:=r.Read(context.Background(),s.URL,m,0);err==nil{t.Fatalf("%s permitted",m)}
 }
}
func TestTruncationBound(t *testing.T){
 r,s:=local(t,http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){_,_=w.Write([]byte(strings.Repeat("Z",MaxBody+100)))}))
 out,err:=r.Read(context.Background(),s.URL,"GET",0)
 if err!=nil||!out.Truncated||out.BytesRead!=MaxBody{t.Fatalf("out=%+v err=%v",out,err)}
}
func TestPrivateCIDRs(t *testing.T){
 r,err:=New(Policy{Origins:[]string{"http://localhost:8765"}})
 if err!=nil{t.Fatal(err)}
 if r.allowedIP(net.ParseIP("127.0.0.1"),nil){t.Fatal("DNS-resolved loopback should not be allowed automatically")}
 r,err=New(Policy{Origins:[]string{"http://localhost:8765"},PrivateCIDRs:[]string{"127.0.0.0/8","::1/128"}})
 if err!=nil{t.Fatal(err)}
 if !r.allowedIP(net.ParseIP("127.0.0.1"),nil){t.Fatal("explicitly approved CIDR denied")}
 if r.allowedIP(net.ParseIP("169.254.169.254"),nil){t.Fatal("metadata endpoint should be blocked")}
}
func TestEmptyOrBroadCIDRRejected(t *testing.T){
 for _,c:=range []string{"0.0.0.0/0","::/0","not-a-cidr"}{
  if _,err:=New(Policy{Origins:[]string{"https://example.org"},PrivateCIDRs:[]string{c}});err==nil{t.Fatalf("accepted %s",c)}
 }
}
func TestLiteralIPMustMatch(t *testing.T){
 r,err:=New(Policy{Origins:[]string{"http://127.0.0.1:1234"}});if err!=nil{t.Fatal(err)}
 if !r.allowedIP(net.ParseIP("127.0.0.1"),net.ParseIP("127.0.0.1")){t.Fatal("literal denied")}
 if r.allowedIP(net.ParseIP("127.0.0.2"),net.ParseIP("127.0.0.1")){t.Fatal("literal mismatch allowed")}
}
func TestInvalidOrigins(t *testing.T){
 for _,origin:=range []string{"file:///etc/passwd","http://user:pw@example.org","https://example.org/secret","https://example.org?q=1"}{
  if _,err:=New(Policy{Origins:[]string{origin}});err==nil{t.Fatalf("invalid %q",origin)}
 }
}
func TestPreviewRange(t *testing.T){
 r,s:=local(t,http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){}))
 if _,err:=r.Read(context.Background(),s.URL,"GET",8193);err==nil{t.Fatal("unbounded preview")}
}
