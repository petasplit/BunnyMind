package bunnycrawl

import (
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
)

func localPolicy(serverURL string)bunnyguard.Policy {
 return bunnyguard.Policy{
  EngagementID:"crawler_lab",
  AllowedOrigins:[]string{serverURL},
  AllowedMethods:[]string{"GET","HEAD"},
  MaxNetworkCalls:32,
  MinIntervalMS:0,
  UserAgent:"BunnyMind-ScopedCrawler-Test",
 }
}
func TestCrawlOnlySameOriginSafeReadLinks(t *testing.T){
 var hitExternal,hitLogout int
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path=="/logout"{hitLogout++}
  if strings.Contains(r.Host,"example.invalid"){hitExternal++}
  switch r.URL.Path{
  case "/":
   w.Header().Set("Content-Type","text/html")
   _,_=w.Write([]byte(`<a href="/next">next</a><a href="/logout">signout</a>
     <a href="https://example.invalid/private">external</a>
     <link href="/main.js" rel="modulepreload" />
     <a href="/picture.png">image</a><a href="/next?token=sensitive">query</a>`))
  case "/next":
   w.Header().Set("Content-Type","text/html")
   _,_=w.Write([]byte(`<a href="/">home</a>`))
  case "/main.js":
   w.Header().Set("Content-Type","application/javascript")
   _,_=w.Write([]byte(`console.log("owned test")`))
  default:
   w.WriteHeader(404)
  }
 }))
 defer srv.Close()
 policy:=localPolicy(srv.URL)
 out,err:=Run(context.Background(),Plan{EngagementID:policy.EngagementID,
  SeedURL:srv.URL+"/",MaxPages:4,MaxDepth:2},policy,t.TempDir())
 if err!=nil{t.Fatal(err)}
 if hitExternal!=0||hitLogout!=0{t.Fatal("crawler requested an unapproved or unsafe endpoint")}
 if out.RequestsUsed!=3{t.Fatalf("expected exactly 3 in-scope GETs, got %+v",out)}
 if len(out.DiscoveredPaths)!=3{t.Fatalf("expected root, next and script link candidates; got %+v",out.DiscoveredPaths)}
 for _,p:=range out.DiscoveredPaths{
  if strings.Contains(p,"logout")||strings.Contains(p,"?token")||strings.Contains(p,"example.invalid"){
   t.Fatal("unsafe URL appeared in crawl report")
  }
 }
}
func TestRejectOutOfScopeAndBudgetOverruns(t *testing.T){
 policy:=localPolicy("http://127.0.0.1:18080")
 cases:=[]Plan{
  {EngagementID:policy.EngagementID,SeedURL:"http://127.0.0.1:18081",MaxPages:4,MaxDepth:1},
  {EngagementID:policy.EngagementID,SeedURL:"https://example.org",MaxPages:4,MaxDepth:1},
  {EngagementID:policy.EngagementID,SeedURL:"http://127.0.0.1:18080/%2E%2E/private",MaxPages:4,MaxDepth:1},
  {EngagementID:policy.EngagementID,SeedURL:"http://127.0.0.1:18080",MaxPages:17,MaxDepth:1},
  {EngagementID:policy.EngagementID,SeedURL:"http://127.0.0.1:18080",MaxPages:4,MaxDepth:4},
 }
 for _,p:=range cases{if err:=Validate(p,policy);err==nil{t.Fatalf("unsafe plan accepted %+v",p)}}
}
func TestSafeURLFilteringBlocksSideEffects(t *testing.T){
 base,_:=url.Parse("https://approved.example/app")
 for _,raw:=range []string{
  "/logout","/api/delete-account","/password/reset","//evil.org/token",
  "https://not-approved.example/","javascript:alert(1)","/download.zip",
  "/admin/%2e%2e/private",
 }{
  if _,ok:=permittedLink(base,base,raw);ok{t.Fatalf("unexpectedly followed %q",raw)}
 }
 if resolved,ok:=permittedLink(base,base,"/docs?session=secret");!ok||strings.Contains(resolved,"secret"){
  t.Fatal("GET query values must be stripped before crawling")
 }
}
