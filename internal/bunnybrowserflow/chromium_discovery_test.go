package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "strings"
 "testing"
 "time"

 "github.com/enowdev/antares/internal/browser"
)
func TestChromeAuthDiscoveryLocal(t *testing.T){
 executable:=os.Getenv("BUNNY_CHROME")
 if _,err:=browser.FindExecutable(executable);err!=nil{
  if executable!=""{t.Fatalf("configured Chrome missing: %v",err)}
  t.Skip("Chromium unavailable",err)
 }
 markup:=`<!doctype html><html><head><title>Login</title></head><body>
 <form onsubmit="event.preventDefault();document.getElementById('result').textContent='Signed in';">
 <label for="original-email">Email</label><input id="original-email" type="email" autocomplete="email" name="address">
 <label>Password <input type="password" autocomplete="current-password"></label>
 <button type="submit">Sign in</button>
 </form><div id="result"></div></body></html>`
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/html")
  _,_=w.Write([]byte(markup))
 }))
 defer server.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),70*time.Second)
 defer cancel()
 s:=browser.New(browser.Options{Executable:executable,Headless:true,LoopbackOrigin:server.URL})
 defer s.Stop()
 driver:=&chromeDriver{session:s}
 if err:=driver.Navigate(ctx,server.URL);err!=nil{t.Fatal(err)}
 state,err:=driver.DiscoverAuth(ctx)
 if err!=nil{t.Fatal(err)}
 preserved,err:=s.EvalString(ctx,"document.getElementById('original-email') ? 'yes' : 'no'")
 if err!=nil||preserved!="yes"{t.Fatal("form discovery mutated an application-owned input ID")}
  if state.Kind!="login"||state.Ambiguous||len(state.Fields)!=2||state.SubmitSelector==""{
  t.Fatalf("form not classified: %+v",state)
 }
 for _,field:=range state.Fields{
  value:="test@example.test"
  if field.Role=="password"{value="SecretPasswordValue123!"}
  if err:=driver.Fill(ctx,field.Selector,value);err!=nil{t.Fatalf("fill %s: %v",field.Role,err)}
 }
 after,err:=driver.DiscoverAuth(ctx)
 if err!=nil{t.Fatal(err)}
 bytes,_:=json.Marshal(after)
 if strings.Contains(string(bytes),"SecretPasswordValue123")||strings.Contains(string(bytes),"test@example.test"){
  t.Fatal("discovery leaked input credentials")
 }
 if err:=driver.Click(ctx,state.SubmitSelector);err!=nil{t.Fatal(err)}
 ok,err:=driver.Contains(ctx,"Signed in")
 if err!=nil||!ok{t.Fatalf("dynamic form submission not executed: %v",err)}
}
