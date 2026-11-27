// BunnyMind local remediation demonstration using two disposable loopback
// applications and freshly generated, synthetic test-user credentials.
package main

import (
 "context"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "flag"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"

 "github.com/enowdev/antares/internal/bunnyauthz"
 "github.com/enowdev/antares/internal/bunnybuild"
 "github.com/enowdev/antares/internal/bunnyfix"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)
const marker = "SYNTHETIC_LOCAL_OWNER_ACCESS_MARKER"
func testToken()(string,error){
 b:=make([]byte,32)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(b),nil
}
func main(){
 mode:=flag.String("mode","remediation","remediation, regression, persistent, or denied")
 jsonOnly:=flag.Bool("json",false,"emit machine-readable JSON only")
 bound:=flag.Bool("build-bound",false,"sign and verify two distinct measured synthetic artifact files")
 flag.Parse()
 var firstExposed,secondExposed bool
 expected:=""
 switch *mode{
 case "remediation": firstExposed=true;secondExposed=false;expected="remediation_observed_in_lab"
 case "regression": firstExposed=false;secondExposed=true;expected="regression_observed_in_lab"
 case "persistent": firstExposed=true;secondExposed=true;expected="unchanged_exposure_in_lab"
 case "denied": firstExposed=false;secondExposed=false;expected="unchanged_denial_in_lab"
 default:fmt.Fprintln(os.Stderr,"invalid synthetic scenario mode");os.Exit(2)
 }
 owner,err:=testToken()
 if err!=nil{fail(err)}
 foreign,err:=testToken()
 if err!=nil{fail(err)}
 public,private,err:=bunnyreceipt.Keypair()
 if err!=nil{fail(err)}
 fixture:=func(exposed bool)*httptest.Server{
  return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
   if r.Method!="GET"||r.URL.Path!="/accounts/owner"{w.WriteHeader(404);return}
   switch r.Header.Get("Authorization"){
   case "Bearer "+owner:_,_=w.Write([]byte(marker))
   case "Bearer "+foreign:
    if exposed{_,_=w.Write([]byte(marker))}else{w.WriteHeader(403)}
   default:w.WriteHeader(401)
   }
  }))
 }
 beforeServer:=fixture(firstExposed);defer beforeServer.Close()
 afterServer:=fixture(secondExposed);defer afterServer.Close()
 makePlan:=func(origin,run string)bunnyauthz.Plan{
  return bunnyauthz.Plan{EngagementID:"local_remediation_demo",RunID:run,
   CaseID:"owner_resource",Origin:origin,ResourcePath:"/accounts/owner",Marker:marker}
 }
 beforePlan:=makePlan(beforeServer.URL,"before_build")
 afterPlan:=makePlan(afterServer.URL,"after_build")
 var beforeBuild,afterBuild bunnybuild.Signed
 if *bound{
  dir,err:=os.MkdirTemp("","bunnymind-build-bound-*")
  if err!=nil{fail(err)}
  defer os.RemoveAll(dir)
  beforePath:=filepath.Join(dir,"before-build.bin")
  afterPath:=filepath.Join(dir,"after-build.bin")
  // Explicitly illustrative file bytes. We do NOT claim the test server is
  // executing these artifacts; the two receipts only prove the recorder
  // measured these local files and attached their hashes.
  if err:=os.WriteFile(beforePath,[]byte("synthetic-before-application-artifact"),0600);err!=nil{fail(err)}
  if err:=os.WriteFile(afterPath,[]byte("synthetic-after-application-artifact"),0600);err!=nil{fail(err)}
  beforeBuild,err=bunnybuild.MeasureAndSign(beforePath,beforePlan.EngagementID,beforePlan.RunID,private)
  if err!=nil{fail(err)}
  afterBuild,err=bunnybuild.MeasureAndSign(afterPath,afterPlan.EngagementID,afterPlan.RunID,private)
  if err!=nil{fail(err)}
  beforePlan.BuildSHA256=beforeBuild.Record.ArtifactSHA256
  afterPlan.BuildSHA256=afterBuild.Record.ArtifactSHA256
 }
 personas:=bunnyauthz.Tokens{Owner:owner,Foreign:foreign}
 before,err:=bunnyauthz.Record(context.Background(),beforePlan,private,personas)
 if err!=nil{fail(err)}
 after,err:=bunnyauthz.Record(context.Background(),afterPlan,private,personas)
 if err!=nil{fail(err)}
 pair:=bunnyfix.Pair{BeforePlan:beforePlan,
  BeforeCapture:before,AfterPlan:afterPlan,AfterCapture:after}
 var result any
 outcome:=""
 if *bound {
  assessed,err:=bunnyfix.CompareBuildBound(public,bunnyfix.BuildBoundPair{
   Pair:pair,BeforeBuild:beforeBuild,AfterBuild:afterBuild,
  })
  if err!=nil{fail(err)}
  result=assessed
  outcome=assessed.Comparison.Outcome
 }else{
  assessed,err:=bunnyfix.Compare(public,pair)
  if err!=nil{fail(err)}
  result=assessed
  outcome=assessed.Outcome
 }
 data,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{fail(err)}
 if !*jsonOnly{
  fmt.Println("BunnyMind synthetic remediation demo")
  fmt.Println("Warning: signer and both fixtures run in the same process. This is not production fix attestation.")
 }
 fmt.Println(string(data))
 if outcome!=expected{
  fmt.Fprintln(os.Stderr,"synthetic remediation scenario did not match expected outcome")
  os.Exit(1)
 }
}
func fail(err error){fmt.Fprintln(os.Stderr,err);os.Exit(1)}
