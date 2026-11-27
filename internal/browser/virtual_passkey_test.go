package browser

import (
 "context"
 "net/http"
 "net/http/httptest"
 "os"
 "testing"
 "time"
)
func TestVirtualWebAuthnRequiresScopedTestBrowser(t *testing.T){
 s:=New(Options{VirtualPasskey:true,Headless:true})
 ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
 defer cancel()
 if err:=s.Start(ctx);err==nil{
  s.Stop()
  t.Fatal("virtual WebAuthn permitted without controlled browser scope")
 }
}
func TestChromeVirtualWebAuthnTestAuthenticator(t *testing.T){
 chrome:=os.Getenv("BUNNY_CHROME")
 if _,err:=FindExecutable(chrome);err!=nil{
  if chrome!=""{t.Fatal(err)}
  t.Skip("Chromium not installed")
 }
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  _,_=w.Write([]byte("<!doctype html><title>WebAuthn staging</title>"))
 }))
 defer server.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),70*time.Second)
 defer cancel()
 s:=New(Options{Executable:chrome,Headless:true,LoopbackOrigin:server.URL,VirtualPasskey:true})
 defer s.Stop()
 if err:=s.Navigate(ctx,server.URL);err!=nil{t.Fatal(err)}
 if !s.VirtualPasskeyReady(){t.Fatal("WebAuthn virtual CTAP2 authenticator was not installed")}
}
func TestPopupAuthorizationNeverAcceptsUnlistedHost(t *testing.T){
 allowed:=map[string]bool{"https://idp.example":true}
 for _,raw:=range []string{"https://idp.example.evil.test/login","https://evil.test/","http://idp.example/login",
  "https://user:secret@idp.example/login","file:///etc/passwd"}{
  if popupInScope(raw,allowed){t.Fatalf("popup origin escaped approval: %q",raw)}
 }
 if !popupInScope("https://idp.example/login?state=opaque",allowed){
  t.Fatal("explicit approved IdP origin rejected")
 }
 if !popupInScope("about:blank",allowed){
  t.Fatal("frozen initial popup tab must be eligible for scoped intercept")
 }
}
