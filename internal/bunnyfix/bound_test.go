package bunnyfix

import (
 "context"
 "crypto/ed25519"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyauthz"
 "github.com/enowdev/antares/internal/bunnybuild"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)
func boundRun(t *testing.T,private ed25519.PrivateKey,run,content string,exposed bool)(bunnyauthz.Plan,bunnyauthz.Capture,bunnybuild.Signed){
 t.Helper()
 artifact:=filepath.Join(t.TempDir(),"synthetic-application.bin")
 if err:=os.WriteFile(artifact,[]byte(content),0600);err!=nil{t.Fatal(err)}
 measured,err:=bunnybuild.MeasureAndSign(artifact,"isolated_demo",run,private)
 if err!=nil{t.Fatal(err)}
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Method!="GET"||r.URL.Path!="/accounts/owner"{w.WriteHeader(404);return}
  switch r.Header.Get("Authorization"){
  case "Bearer "+owner:_,_=w.Write([]byte(marker))
  case "Bearer "+foreign:
   if exposed{_,_=w.Write([]byte(marker))}else{w.WriteHeader(403)}
  default:w.WriteHeader(401)
  }
 }))
 t.Cleanup(server.Close)
 plan:=bunnyauthz.Plan{
  EngagementID:"isolated_demo",RunID:run,CaseID:"owner_resource",
  Origin:server.URL,ResourcePath:"/accounts/owner",Marker:marker,
  BuildSHA256:measured.Record.ArtifactSHA256,
 }
 captured,err:=bunnyauthz.Record(context.Background(),plan,private,bunnyauthz.Tokens{Owner:owner,Foreign:foreign})
 if err!=nil{t.Fatal(err)}
 return plan,captured,measured
}
func boundPair(t *testing.T,beforeContent,afterContent string)(ed25519.PublicKey,BuildBoundPair){
 t.Helper()
 pub,priv,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)}
 before,cBefore,attBefore:=boundRun(t,priv,"before_run",beforeContent,true)
 after,cAfter,attAfter:=boundRun(t,priv,"after_run",afterContent,false)
 return pub,BuildBoundPair{
  Pair:Pair{BeforePlan:before,BeforeCapture:cBefore,AfterPlan:after,AfterCapture:cAfter},
  BeforeBuild:attBefore,AfterBuild:attAfter,
 }
}
func TestBuildBoundRemediationWithDistinctFiles(t *testing.T){
 pub,p:=boundPair(t,"deliberately vulnerable fixture bytes v1","safe fixture bytes v2")
 got,err:=CompareBuildBound(pub,p)
 if err!=nil{t.Fatal(err)}
 if got.Comparison.Outcome!="remediation_observed_in_lab"||!got.ArtifactMeasurementsAuthenticated||
  got.DeploymentIdentityVerified||got.BeforeArtifactSHA256==got.AfterArtifactSHA256{
  t.Fatalf("invalid build-bound conclusion %+v",got)
 }
}
func TestSameArtifactRejected(t *testing.T){
 pub,p:=boundPair(t,"same synthetic code","same synthetic code")
 if _,err:=CompareBuildBound(pub,p);err==nil{t.Fatal("same file bytes treated as changed build")}
}
func TestTamperedArtifactMeasurementRejected(t *testing.T){
 pub,p:=boundPair(t,"synthetic v1","synthetic v2")
 p.AfterBuild.Record.ArtifactBytes++
 if _,err:=CompareBuildBound(pub,p);err==nil{t.Fatal("tampered artifact measurement accepted")}
}
func TestSwappedBuildRunRejected(t *testing.T){
 pub,p:=boundPair(t,"synthetic v1","synthetic v2")
 p.BeforeBuild,p.AfterBuild=p.AfterBuild,p.BeforeBuild
 if _,err:=CompareBuildBound(pub,p);err==nil{t.Fatal("swapped run measurements accepted")}
}
func TestSignedReceiptMismatchedFingerprintRejected(t *testing.T){
 pub,p:=boundPair(t,"synthetic v1","synthetic v2")
 p.Pair.BeforePlan.BuildSHA256=p.AfterBuild.Record.ArtifactSHA256
 if _,err:=CompareBuildBound(pub,p);err==nil{t.Fatal("inconsistent receipt-to-artifact mapping accepted")}
}
func TestMissingBuildBoundReceiptRejected(t *testing.T){
 pub,p:=boundPair(t,"synthetic v1","synthetic v2")
 p.Pair.AfterCapture.CrossUserBundle.Receipts[0].Observation.BuildSHA256=""
 if _,err:=CompareBuildBound(pub,p);err==nil{t.Fatal("unbound sample accepted")}
}
func TestWrongSignerRejected(t *testing.T){
 _,p:=boundPair(t,"synthetic v1","synthetic v2")
 wrong,_,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)}
 if _,err:=CompareBuildBound(wrong,p);err==nil{t.Fatal("wrong recorder key accepted")}
}
func TestDoesNotLeakRawBytesOrBearerSecrets(t *testing.T){
 pub,p:=boundPair(t,"synthetic v1","synthetic v2")
 out,err:=CompareBuildBound(pub,p);if err!=nil{t.Fatal(err)}
 data,_:=json.Marshal(out)
 for _,word:=range []string{"synthetic v1","synthetic v2",owner,foreign,marker}{
  if strings.Contains(string(data),word){t.Fatal("sensitive content in build comparison")}
 }
}
