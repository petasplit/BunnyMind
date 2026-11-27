package bunnyguard

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func fixture(t *testing.T,max int)(*Guard,string){
 t.Helper()
 path:=filepath.Join(t.TempDir(),"policy.json")
 b,_:=json.Marshal(Policy{EngagementID:"local-lab",AllowedOrigins:[]string{"http://127.0.0.1:8765"},AllowedMethods:[]string{"GET","POST"},MaxNetworkCalls:max})
 if err:=os.WriteFile(path,b,0600);err!=nil{t.Fatal(err)}
 g,err:=New(path);if err!=nil{t.Fatal(err)}
 return g,path
}
func TestExactOrigin(t *testing.T){
 g,_:=fixture(t,10)
 for _,tc:=range []struct{url string;ok bool}{
 {"http://127.0.0.1:8765/health",true},
 {"http://127.0.0.1:8766/health",false},
 {"http://127.0.0.1.evil.test:8765/",false},
 {"https://127.0.0.1:8765/",false},
 {"http://user:password@127.0.0.1:8765/",false},
 }{
  b,_:=json.Marshal(map[string]string{"url":tc.url})
  if got:=g.Evaluate("x","scoped_read",string(b)).Allowed;got!=tc.ok{t.Errorf("%s got=%v",tc.url,got)}
 }
}
func TestMethodsAndBudget(t *testing.T){
 g,path:=fixture(t,2)
 if g.Evaluate("x","scoped_read",`{"method":"DELETE","url":"http://127.0.0.1:8765/"}`).Allowed{t.Fatal("DELETE approved")}
 for i:=0;i<2;i++{
  if !g.Evaluate("x","scoped_read",`{"url":"http://127.0.0.1:8765/"}`).Allowed{t.Fatal("approved request denied")}
 }
 again,err:=New(path);if err!=nil{t.Fatal(err)}
 if again.Evaluate("y","scoped_read",`{"url":"http://127.0.0.1:8765/"}`).Allowed{t.Fatal("budget reset after restart")}
}
func TestDangerousOrUnknownToolsDenied(t *testing.T){
 g,_:=fixture(t,4)
 for _,tool:=range []string{"terminal","http_request","web_fetch","browser","hackbrowser","delegate_task","vps_run","unrecognized_mcp_tool"}{
  if g.Evaluate("x",tool,`{}`).Allowed{t.Fatalf("%s allowed",tool)}
 }
}
func TestAuditRedactedAndTamperDetected(t *testing.T){
 g,p:=fixture(t,2)
 g.Evaluate("x","scoped_read",`{"url":"http://127.0.0.1:8765/?secret=SYNTHETIC_PRIVATE"}`)
 log:=filepath.Join(filepath.Dir(p),"bunnyguard-audit.jsonl")
 b,err:=os.ReadFile(log);if err!=nil{t.Fatal(err)}
 if strings.Contains(string(b),"SYNTHETIC_PRIVATE"){t.Fatal("private data in audit")}
 modified:=strings.Replace(string(b),`"tool":"scoped_read"`,`"tool":"terminal"`,1)
 if err:=os.WriteFile(log,[]byte(modified),0600);err!=nil{t.Fatal(err)}
 if _,err:=VerifyAudit(p);err==nil{t.Fatal("tamper undetected")}
}
func TestInvalidManifestRejected(t *testing.T){
 p:=filepath.Join(t.TempDir(),"invalid.json")
 if err:=os.WriteFile(p,[]byte(`{"engagement_id":"x","allowed_origins":[],"max_network_calls":0}`),0600);err!=nil{t.Fatal(err)}
 if _,err:=New(p);err==nil{t.Fatal("invalid policy accepted")}
}
