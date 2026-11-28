package server

import (
 "io/fs"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "testing/fstest"
)

func testDashboardFiles() fs.FS {
 return fstest.MapFS{
  "index.html":{Data:[]byte("<!doctype html><html><body><script type=\"module\" src=\"/assets/app-123.js\"></script></body></html>")},
  "assets/app-123.js":{Data:[]byte("export const ready = true;")},
  "assets/ChatPage-test123.js":{Data:[]byte("export default function ChatPage() {}")},
 }
}

func TestDashboardModuleIsAvailableWithJavaScriptMIME(t *testing.T){
 s:=&Server{distFS:testDashboardFiles()}
 for _,url:=range []string{"/assets/app-123.js","/assets/ChatPage-test123.js"}{
  rec:=httptest.NewRecorder()
  s.handleDashboard(rec,httptest.NewRequest(http.MethodGet,url,nil))
  if rec.Code!=http.StatusOK{t.Fatalf("%s returned %d",url,rec.Code)}
  if ct:=rec.Header().Get("Content-Type");!strings.Contains(ct,"javascript"){
   t.Fatalf("%s returned non-JavaScript Content-Type %q",url,ct)
  }
  if !strings.Contains(rec.Header().Get("Cache-Control"),"immutable"){
   t.Fatalf("%s does not have immutable cache policy",url)
  }
 }
}

func TestMissingHashedAssetCannotReturnSPAHTML(t *testing.T){
 s:=&Server{distFS:testDashboardFiles()}
 for _,url:=range []string{"/assets/ChatPage-stale.js","/assets/missing.css"}{
  rec:=httptest.NewRecorder()
  s.handleDashboard(rec,httptest.NewRequest(http.MethodGet,url,nil))
  if rec.Code!=http.StatusNotFound{t.Fatalf("%s returned %d rather than 404",url,rec.Code)}
  if strings.Contains(rec.Body.String(),"<html"){t.Fatal("missing module accidentally served SPA HTML")}
  if rec.Header().Get("Cache-Control")!="no-store"{
   t.Fatal("missing asset response must not be cached")
  }
 }
}

func TestDashboardDeepLinkStillServesIndex(t *testing.T){
 s:=&Server{distFS:testDashboardFiles()}
 rec:=httptest.NewRecorder()
 s.handleDashboard(rec,httptest.NewRequest(http.MethodGet,"/security/findings",nil))
 if rec.Code!=http.StatusOK || !strings.Contains(rec.Body.String(),"<html"){
  t.Fatalf("SPA deep route should serve index, got %d %s",rec.Code,rec.Body.String())
 }
 if rec.Header().Get("Cache-Control")!="no-cache"{t.Fatal("index must be revalidated")}
}
