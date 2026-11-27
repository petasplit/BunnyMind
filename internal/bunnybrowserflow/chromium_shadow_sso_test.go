package bunnybrowserflow

import (
 "context"
 "net/http"
 "net/http/httptest"
 "os"
 "strings"
 "testing"
 "time"

 "github.com/enowdev/antares/internal/browser"
)
func TestChromeShadowDOMAndApprovedSSOLinks(t *testing.T){
 executable:=os.Getenv("BUNNY_CHROME")
 if _,err:=browser.FindExecutable(executable);err!=nil{
  if executable!=""{t.Fatal(err)}
  t.Skip("Chromium not installed")
 }
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/html")
  _,_=w.Write([]byte(`<!doctype html><title>Enterprise login</title>
  <main id="host"></main><p id="out"></p>
  <a href="https://idp.example/authorize?state=private" id="sso">Sign in with SSO</a>
  <script>
   const root=document.querySelector('#host').attachShadow({mode:'open'});
   root.innerHTML='<input id="owned-email" type="email"><input type="password" name="password"><button type="submit">Sign in</button>';
   root.querySelector('button').onclick=() => document.querySelector('#out').textContent='Authenticated in staging';
  </script>`))
 }))
 defer server.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
 defer cancel()
 s:=browser.New(browser.Options{Executable:executable,Headless:true,LoopbackOrigin:server.URL})
 defer s.Stop()
 d:=&chromeDriver{session:s}
 if err:=d.Navigate(ctx,server.URL);err!=nil{t.Fatal(err)}
 state,err:=d.DiscoverAuthScoped(ctx,[]string{"https://idp.example"})
 if err!=nil{t.Fatal(err)}
 if state.ProviderSelector==""||len(state.Fields)!=2||state.SubmitSelector==""{
  t.Fatalf("shadow roots/SSO not detected: %+v",state)
 }
 for _,field:=range state.Fields{
  value:="owner@example.test"
  if field.Role=="password"{value="private-test-password"}
  if err:=d.Fill(ctx,field.Selector,value);err!=nil{t.Fatalf("fill shadow %s: %v",field.Role,err)}
 }
 preserved,err:=s.EvalString(ctx,"document.querySelector('#host').shadowRoot.getElementById('owned-email')?'yes':'no'")
 if err!=nil||preserved!="yes"{t.Fatal("shadow discovery damaged application-owned element IDs")}
 if err:=d.Click(ctx,state.SubmitSelector);err!=nil{t.Fatal(err)}
 ok,err:=d.Contains(ctx,"Authenticated in staging")
 if err!=nil||!ok{t.Fatalf("shadow submit did not update SPA: %v",err)}
 // A provider outside operator-approved origins must not surface as a click.
 noProvider,err:=d.DiscoverAuth(ctx)
 if err!=nil||noProvider.ProviderSelector!=""{t.Fatalf("unapproved SSO shown: %+v %v",noProvider,err)}
 if strings.Contains(state.ProviderSelector,"state=private"){t.Fatal("SSO query token leaked in discovered metadata")}
}
