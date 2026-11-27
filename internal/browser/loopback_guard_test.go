package browser

import (
 "context"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "testing"
 "time"
)

func TestLoopbackOriginPreflight(t *testing.T){
 for _,good:=range []string{"http://127.0.0.1:3000","http://[::1]:8000"}{
  if _,err:=parseLoopbackOrigin(good);err!=nil{t.Fatalf("rejected local fixture %q: %v",good,err)}
 }
 for _,bad:=range []string{"https://127.0.0.1:3000","http://localhost:3000","http://192.168.1.5:8000",
 "http://10.0.0.5:3000","http://169.254.169.254:80","http://127.0.0.1",
 "http://127.0.0.1:8000/path","http://user:pass@127.0.0.1:8000"}{
  if _,err:=parseLoopbackOrigin(bad);err==nil{t.Fatalf("accepted nonfixture origin %q",bad)}
 }
}
func TestLoopbackRequestFilterAndBudget(t *testing.T){
 g:=&loopbackGate{origin:"http://127.0.0.1:3000"}
 for _,method:=range []string{"GET","POST","OPTIONS","HEAD"}{
  if !g.allow("http://127.0.0.1:3000/resource",method){t.Fatalf("method %s rejected",method)}
 }
 for _,tc:=range []struct{url,method string}{
  {"http://127.0.0.1:3001/resource","GET"},
  {"http://10.0.0.2:3000","GET"},
  {"http://user:pass@127.0.0.1:3000/","GET"},
  {"https://127.0.0.1:3000/","GET"},
  {"http://127.0.0.1:3000/","DELETE"},
  {"file:///etc/passwd","GET"},
 }{
  if g.allow(tc.url,tc.method){t.Fatalf("permitted %s %s",tc.method,tc.url)}
 }
 for i:=4;i<maxLoopbackRequests;i++{
  if !g.allow("http://127.0.0.1:3000/", "GET"){t.Fatal("premature request limit")}
 }
 if g.allow("http://127.0.0.1:3000/","GET"){t.Fatal("missing request budget")}
}
func TestChromiumNetworkInterceptorBlocksOtherLocalPort(t *testing.T){
 if _,err:=FindExecutable("");err!=nil{t.Skip("Chrome unavailable:",err)}
 var otherCalls atomic.Int64
 other:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  otherCalls.Add(1)
  w.WriteHeader(200)
 }))
 defer other.Close()
 site:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/html; charset=utf-8")
  _,_=w.Write([]byte("<!doctype html><h1>Trusted page</h1><script>fetch('"+other.URL+"/forbidden').catch(()=>{})</script>"))
 }))
 defer site.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),70*time.Second)
 defer cancel()
 s:=New(Options{Headless:true,LoopbackOrigin:site.URL})
 defer s.Stop()
 if err:=s.Navigate(ctx,site.URL);err!=nil{t.Fatal(err)}
 time.Sleep(700*time.Millisecond)
 if n:=otherCalls.Load();n!=0{t.Fatalf("browser contacted off-origin local fixture %d times",n)}
}
func TestLoopbackBrowserRejectsPersistentOrProxyProfiles(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
 defer cancel()
 for _,opt:=range []Options{
  {LoopbackOrigin:"http://127.0.0.1:8000",RemoteURL:"http://127.0.0.1:9222"},
  {LoopbackOrigin:"http://127.0.0.1:8000",UserDataDir:"/tmp/user"},
  {LoopbackOrigin:"http://127.0.0.1:8000",Proxy:"http://127.0.0.1:1080"},
  {LoopbackOrigin:"http://127.0.0.1:8000",Stealth:true},
 }{
  s:=New(opt)
  if err:=s.Start(ctx);err==nil{s.Stop();t.Fatal("browser isolation preflight accepted unsafe options")}
 }
}
