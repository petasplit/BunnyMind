package browser

import (
 "context"
 "net/http"
 "net/http/httptest"
 "os"
 "strings"
 "testing"
 "time"
)
func TestChromeScopedPopupNavigationAndRestore(t *testing.T){
 executable:=os.Getenv("BUNNY_CHROME")
 if _,err:=FindExecutable(executable);err!=nil{
  if executable!=""{t.Fatal(err)}
  t.Skip("Chromium unavailable")
 }
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/html; charset=utf-8")
  if r.URL.Path=="/popup"{
   _,_=w.Write([]byte("<!doctype html><title>SSO Popup</title><h1>Identity-provider test window</h1>"))
   return
  }
  _,_=w.Write([]byte("<!doctype html><title>App Parent</title><button id='launch' onclick=\"window.open('/popup','_blank')\">Open SSO</button>"))
 }))
 defer server.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),80*time.Second)
 defer cancel()
 s:=New(Options{Executable:executable,LoopbackOrigin:server.URL,Headless:true})
 defer s.Stop()
 if err:=s.Navigate(ctx,server.URL);err!=nil{t.Fatal(err)}
 _,err:=s.Eval(ctx,"document.querySelector('#launch').click()")
 if err!=nil{t.Fatal(err)}
 switched,err:=s.SwitchToApprovedPopup(ctx)
 if err!=nil||!switched{
  if s.conn!=nil{
   if raw,e:=s.conn.send(ctx,"","Target.getTargets",nil);e==nil{t.Logf("CDP local test target inventory: %s",raw)}
  }
  t.Fatalf("popup wasn't attached under scope: %v switched=%v",err,switched)
 }
 title,err:=s.Title(ctx)
 if err!=nil||title!="SSO Popup"{t.Fatalf("popup title %q error %v",title,err)}
 if err:=s.RestoreMainPage();err!=nil{t.Fatal(err)}
 parent,err:=s.Title(ctx)
 if err!=nil||parent!="App Parent"{t.Fatalf("original tab lost %q %v",parent,err)}
}
func TestLocalPopupScopeRejectsOtherLoopbackPort(t *testing.T){
 allowed:=map[string]bool{"http://127.0.0.1:3000":true}
 if !popupInScope("http://127.0.0.1:3000/verified",allowed){t.Fatal("approved local popup denied")}
 for _,dest:=range []string{
  "http://127.0.0.1:3001/","http://localhost:3000/",
  "http://169.254.169.254/","https://evil.example/",
 }{
  if popupInScope(dest,allowed){t.Fatalf("offscope popup permitted %s",dest)}
 }
}
func TestPopupURINeverExposedByPublicSwitcher(t *testing.T){
 allowed:=map[string]bool{"https://idp.example":true}
 raw:="https://idp.example/callback?state=secret&code=private"
 if !popupInScope(raw,allowed){t.Fatal("approved IdP callback disallowed")}
 if strings.Contains("approved_popup",raw){t.Fatal("raw OAuth code in public event")}
}
