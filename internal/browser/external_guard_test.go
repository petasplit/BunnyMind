package browser

import (
 "context"
 "testing"
 "time"
)
func TestExternalBrowserAllowlistAndPosts(t *testing.T){
 g,err:=newExternalGate([]string{"https://app.example"},[]string{"/login","/signup"},5,0)
 if err!=nil{t.Fatal(err)}
 if !g.allow("https://app.example/","GET"){t.Fatal("allowed GET rejected")}
 if !g.allow("https://app.example/login","POST"){t.Fatal("approved POST rejected")}
 for _,r:=range []struct{url,method string}{
  {"https://evil.example/login","POST"},
  {"https://app.example/transfer","POST"},
  {"http://app.example/login","POST"},
  {"https://user:pass@app.example/login","GET"},
  {"https://app.example:4443/login","GET"},
  {"file:///etc/passwd","GET"},
  {"https://app.example/login","DELETE"},
 }{
  if g.allow(r.url,r.method){t.Fatalf("allowed unapproved %s %s",r.method,r.url)}
 }
 for i:=2;i<5;i++{
  if !g.allow("https://app.example/","GET"){t.Fatalf("premature budget at %d",i)}
 }
 if g.allow("https://app.example/","GET"){t.Fatal("over budget allowed")}
}
func TestExternalProxyMustBeLocalAndExact(t *testing.T){
 for _,value:=range []string{"http://127.0.0.1:9999","http://127.0.0.1:80"}{
  if _,err:=externalProxyAddress(value);err!=nil{t.Fatal(err)}
 }
 for _,raw:=range []string{"http://localhost:8080","http://10.0.0.1:8080",
  "https://127.0.0.1:9000","http://127.0.0.1:8080/path",
  "http://user:pass@127.0.0.1:8080","http://127.0.0.1:0"}{
  if _,err:=externalProxyAddress(raw);err==nil{t.Fatalf("unsafe proxy accepted %q",raw)}
 }
}
func TestExternalGateEnforcesPacing(t *testing.T){
 g,err:=newExternalGate([]string{"https://approved.example"},nil,3,40)
 if err!=nil{t.Fatal(err)}
 start:=time.Now()
 if !g.allow("https://approved.example/","GET")||!g.allow("https://approved.example/","GET"){
  t.Fatal("request pacing refused approved calls")
 }
 if time.Since(start)<35*time.Millisecond{t.Fatal("minimum interval not honored")}
}
func TestExternalBrowserFailsPreflightWithoutProxy(t *testing.T){
 for _,opts:=range []Options{
  {ExternalOrigins:[]string{"https://approved.example"},ExternalMaxRequests:10},
  {ExternalOrigins:[]string{"https://approved.example"},ExternalMaxRequests:10,ExternalProxyURL:"http://localhost:9999"},
  {ExternalOrigins:[]string{"https://approved.example"},ExternalMaxRequests:10,ExternalProxyURL:"http://127.0.0.1:9000",RemoteURL:"http://127.0.0.1:9222"},
  {ExternalOrigins:[]string{"https://approved.example"},ExternalMaxRequests:10,ExternalProxyURL:"http://127.0.0.1:9000",Stealth:true},
  {ExternalOrigins:[]string{"https://approved.example"},ExternalMaxRequests:10,ExternalProxyURL:"http://127.0.0.1:9000",UserDataDir:"profile"},
 }{
  s:=New(opts)
  ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
  err:=s.Start(ctx)
  cancel()
  if err==nil {s.Stop();t.Fatalf("accepted unsafe browser %+v",opts)}
 }
}
