package browser

import "testing"

func TestExternalGateReadOnlyAfterLogin(t *testing.T) {
 g,err:=newExternalGate([]string{"https://approved.example"},[]string{"/login"},16,0)
 if err!=nil{t.Fatal(err)}
 if !g.allow("https://approved.example/login","POST"){t.Fatal("approved login POST unexpectedly blocked")}
 g.readOnly.Store(true)
 for _,req:=range []struct{URL,Method string}{
  {"https://approved.example/login","POST"},
  {"https://approved.example/login","OPTIONS"},
  {"https://approved.example/api/delete","DELETE"},
  {"https://approved.example.evil.invalid/","GET"},
 }{
  if g.allow(req.URL,req.Method){t.Fatalf("read-only gate allowed %s %s",req.Method,req.URL)}
 }
 if !g.allow("https://approved.example/dashboard","GET"){t.Fatal("GET unexpectedly blocked after login")}
 if !g.allow("https://approved.example/assets/app.js","HEAD"){t.Fatal("HEAD unexpectedly blocked after login")}
}
func TestCannotLockUnstartedExternalBrowser(t *testing.T){
 s:=New(Options{})
 if err:=s.LockExternalReadOnly();err==nil{t.Fatal("uninitialized browser entered protected state")}
}
