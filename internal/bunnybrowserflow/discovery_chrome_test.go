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
func TestChromeDiscoversUnfamiliarAuthenticationForm(t *testing.T){
 chromePath:=os.Getenv("BUNNY_CHROME")
 if _,err:=browser.FindExecutable(chromePath);err!=nil{
  if chromePath!=""{t.Fatalf("configured Chrome missing: %v",err)}
  t.Skip("Chrome unavailable")
 }
 site:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/html; charset=utf-8")
  _,_=w.Write([]byte(`<!doctype html><html><body>
  <h2>Create your test profile</h2>
  <form><label>Email<input type="email" name="contact_email" placeholder="private-person@example.test"></label>
  <label>Password<input type="password" name="passcode"></label>
  <button type="button">Create account</button></form>
  <a href="/login">Sign in</a>
  </body></html>`))
 }))
 defer site.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),75*time.Second)
 defer cancel()
 s:=browser.New(browser.Options{Executable:chromePath,Headless:true,LoopbackOrigin:site.URL})
 defer s.Stop()
 if err:=s.Navigate(ctx,site.URL);err!=nil{t.Fatal(err)}
 driver:=&chromeDriver{session:s}
 snap,err:=driver.InspectAuth(ctx)
 if err!=nil{t.Fatalf("real DOM classifier failed: %v",err)}
 if len(snap.Fields)!=2||len(snap.Actions)!=1||len(snap.Links)!=1{
  t.Fatalf("unexpected discovery summary %+v",snap)
 }
 if snap.Fields[0].Kind!="email"||snap.Fields[1].Kind!="password"||
  snap.Actions[0].Kind!="signup"||snap.Links[0].Path!="/login"{
  t.Fatalf("wrong form classification %+v",snap)
 }
 if snap.SignedIn {t.Fatal("login form incorrectly treated as signed in")}
 data:=snap.Fields[0].Selector+" "+snap.Fields[1].Selector
 if strings.Contains(data,"private-person@example.test"){t.Fatal("input placeholder leaked")}
}
