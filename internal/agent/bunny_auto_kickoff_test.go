package agent

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
)
func testManifest(t *testing.T)string{
 t.Helper()
 p:=filepath.Join(t.TempDir(),"manifest.json")
 b,e:=json.Marshal(bunnyguard.Policy{
  EngagementID:"explicit_test_lab",
  AllowedOrigins:[]string{"https://test.example.org"},
  AllowedMethods:[]string{"GET","HEAD"},MaxNetworkCalls:4,
 })
 if e!=nil{t.Fatal(e)}
 if e:=os.WriteFile(p,b,0600);e!=nil{t.Fatal(e)}
 return p
}
func TestStructuredBriefStartsAuthorizedTarget(t *testing.T){
 policy:=testManifest(t)
 input:="Security assessment, authorized.\nTarget: https://test.example.org/login\nScope: https://test.example.org"
 got,err:=authorizedAutoEngagement(input,policy)
 if err!=nil||got.URL!="https://test.example.org/login"{t.Fatalf("target=%q err=%v",got.URL,err)}
}
func TestStructuredBriefNotJustBareURL(t *testing.T){
 policy:=testManifest(t)
 if _,err:=authorizedAutoEngagement("Please check https://test.example.org/",policy);err==nil{t.Fatal("bare URL triggered automatic network request")}
}
func TestNoScopeLineNoKickoff(t *testing.T){
 policy:=testManifest(t)
 if _,err:=authorizedAutoEngagement("Target: https://test.example.org/login",policy);err==nil{t.Fatal("no scope line accepted")}
}
func TestOutOfScopeRejected(t *testing.T){
 policy:=testManifest(t)
 if _,err:=authorizedAutoEngagement("Target: https://outside.example.org\nScope: https://outside.example.org",policy);err==nil{t.Fatal("external origin accepted")}
}
func TestScopeMustMatchTarget(t *testing.T){
 policy:=testManifest(t)
 if _,err:=authorizedAutoEngagement("Target: https://test.example.org\nScope: https://other.example.org",policy);err==nil{t.Fatal("mismatched scope allowed")}
}
func TestRejectUserinfoAndWildcard(t *testing.T){
 policy:=testManifest(t)
 bad:=[]string{
  "Target: https://user:secret@test.example.org\nScope: https://test.example.org",
  "Target: https://test.example.org\nScope: *.example.org",
  "Target: https://test.example.org\nScope: all websites",
 }
 for _,input:=range bad{
  if _,err:=authorizedAutoEngagement(input,policy);err==nil{t.Fatalf("unsafe brief accepted %q",input)}
 }
}
func TestMultipleTargetsRejected(t *testing.T){
 policy:=testManifest(t)
 s:="Target: https://test.example.org/a\nTarget: https://test.example.org/b\nScope: https://test.example.org"
 if _,err:=authorizedAutoEngagement(s,policy);err==nil{t.Fatal("ambiguous two-target request accepted")}
}
func TestStructuredURLParsingPunctuation(t *testing.T){
 policy:=testManifest(t)
 s:="Target: https://test.example.org/a),\nScope: https://test.example.org"
 out,err:=authorizedAutoEngagement(s,policy)
 if err!=nil||!strings.HasSuffix(out.URL,"/a"){t.Fatalf("parsed=%q err=%v",out.URL,err)}
}
