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

 "github.com/enowdev/antares/internal/bunnyauthz"
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
 personas:=bunnyauthz.Tokens{Owner:owner,Foreign:foreign}
 before,err:=bunnyauthz.Record(context.Background(),beforePlan,private,personas)
 if err!=nil{fail(err)}
 after,err:=bunnyauthz.Record(context.Background(),afterPlan,private,personas)
 if err!=nil{fail(err)}
 result,err:=bunnyfix.Compare(public,bunnyfix.Pair{BeforePlan:beforePlan,
  BeforeCapture:before,AfterPlan:afterPlan,AfterCapture:after})
 if err!=nil{fail(err)}
 data,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{fail(err)}
 if !*jsonOnly{
  fmt.Println("BunnyMind synthetic remediation demo")
  fmt.Println("Warning: signer and both fixtures run in the same process. This is not production fix attestation.")
 }
 fmt.Println(string(data))
 if result.Outcome!=expected{
  fmt.Fprintln(os.Stderr,"synthetic remediation scenario did not match expected outcome")
  os.Exit(1)
 }
}
func fail(err error){fmt.Fprintln(os.Stderr,err);os.Exit(1)}
