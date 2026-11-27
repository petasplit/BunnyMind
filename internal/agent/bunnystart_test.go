package agent

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
)
func TestAutoEngagementRequiresExplicitTargetAndScope(t *testing.T){
 for _,message:=range []string{
  "Please tell me about https://example.org",
  "Target: https://example.org",
  "Scope: https://example.org",
  "Target: https://example.org\nScope: another.example",
  "Target: https://example.org\nScope: all internet",
  "Target: https://user:password@example.org\nScope: example.org",
  "Target: https://example.org/?token=abc\nScope: example.org",
  "Target: https://example.org#fragment\nScope: example.org",
 }{
  if _,ok:=parseAutoEngagement(message);ok{t.Fatalf("unqualified scope auto-launched: %q",message)}
 }
}
func TestAutoEngagementParsesTargetBrief(t *testing.T){
 brief,ok:=parseAutoEngagement("Description: Controlled app assessment\n- Target: https://example.org/login\n- Scope: https://example.org\nRules: read-only recon")
 if !ok||brief.URL!="https://example.org/login"||brief.Origin!="https://example.org"{t.Fatalf("%+v %v",brief,ok)}
}
func TestAutoEngagementPausesWithoutManifest(t *testing.T){
 b,message:=authorizedAutoEngagement("Target: https://example.org\nScope: example.org","")
 if b.URL!=""||!strings.Contains(message,"paused"){t.Fatalf("%+v %s",b,message)}
}
func TestAutoEngagementManifestScopeEnforced(t *testing.T){
 p:=filepath.Join(t.TempDir(),"policy.json")
 policy:=bunnyguard.Policy{
  EngagementID:"local-authorized-lab",
  AllowedOrigins:[]string{"http://127.0.0.1:8765"},
  AllowedMethods:[]string{"GET","HEAD"},
  MaxNetworkCalls:5,
 }
 raw,err:=json.Marshal(policy);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(p,raw,0600);err!=nil{t.Fatal(err)}
 valid,notice:=authorizedAutoEngagement("Target: http://127.0.0.1:8765/app\nScope: 127.0.0.1",p)
 if notice!=""||valid.URL==""{t.Fatalf("%+v %s",valid,notice)}
 invalid,notice:=authorizedAutoEngagement("Target: https://example.org\nScope: example.org",p)
 if invalid.URL!=""||!strings.Contains(notice,"outside"){t.Fatalf("%+v %s",invalid,notice)}
}
func TestAutoEngagementRequiresGETApproval(t *testing.T){
 p:=filepath.Join(t.TempDir(),"policy.json")
 raw,_:=json.Marshal(bunnyguard.Policy{EngagementID:"lab",AllowedOrigins:[]string{"http://127.0.0.1:8090"},AllowedMethods:[]string{"HEAD"},MaxNetworkCalls:2})
 if err:=os.WriteFile(p,raw,0600);err!=nil{t.Fatal(err)}
 a,reason:=authorizedAutoEngagement("Target: http://127.0.0.1:8090\nScope: 127.0.0.1",p)
 if a.URL!=""||!strings.Contains(reason,"not approved"){t.Fatalf("%+v %s",a,reason)}
}
func TestAutostartNeverSelectsQueryBearingTarget(t *testing.T){
 for _,url:=range []string{
  "http://127.0.0.1:8080/path?secret=abc",
  "http://user:pass@127.0.0.1:8080/",
  "file:///etc/passwd",
 }{
  if _,ok:=parseAutoEngagement("Target: "+url+"\nScope: 127.0.0.1");ok{
   t.Fatal("unsafe target accepted")
  }
 }
}
