package bunnyfix

import (
 "context"
 "crypto/ed25519"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyauthz"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)
const owner="SYNTHETIC_LAB_OWNER_TOKEN_012345"
const foreign="SYNTHETIC_LAB_FOREIGN_TOKEN_678901"
const marker="SYNTHETIC_OWNER_TEST_RESOURCE_PROOF"
func capture(t *testing.T,priv ed25519.PrivateKey,run string,exposed,ownerDenied bool)(bunnyauthz.Plan,bunnyauthz.Capture){
 t.Helper()
 s:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/accounts/owner"||r.Method!="GET"{w.WriteHeader(404);return}
  switch r.Header.Get("Authorization"){
  case "Bearer "+owner:
   if ownerDenied{w.WriteHeader(403)}else{_,_=w.Write([]byte(marker))}
  case "Bearer "+foreign:
   if exposed{_,_=w.Write([]byte(marker))}else{w.WriteHeader(403)}
  default:w.WriteHeader(401)
  }
 }))
 t.Cleanup(s.Close)
 p:=bunnyauthz.Plan{EngagementID:"isolated_demo",RunID:run,CaseID:"owner_resource",Origin:s.URL,ResourcePath:"/accounts/owner",Marker:marker}
 result,err:=bunnyauthz.Record(context.Background(),p,priv,bunnyauthz.Tokens{Owner:owner,Foreign:foreign})
 if err!=nil{t.Fatal(err)}
 return p,result
}
func pair(t *testing.T,beforeExposed,afterExposed,ownerDenied bool)(ed25519.PublicKey,Pair){
 t.Helper()
 pub,priv,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)}
 b,bc:=capture(t,priv,"before_run",beforeExposed,false)
 a,ac:=capture(t,priv,"after_run",afterExposed,ownerDenied)
 return pub,Pair{BeforePlan:b,BeforeCapture:bc,AfterPlan:a,AfterCapture:ac}
}
func TestRemediationObserved(t *testing.T){
 pub,p:=pair(t,true,false,false)
 r,err:=Compare(pub,p)
 if err!=nil||r.Outcome!="remediation_observed_in_lab"||r.BeforeSignedSamples!=8||r.AfterSignedSamples!=8{t.Fatalf("%+v %v",r,err)}
}
func TestRegressionObserved(t *testing.T){
 pub,p:=pair(t,false,true,false)
 r,err:=Compare(pub,p)
 if err!=nil||r.Outcome!="regression_observed_in_lab"{t.Fatalf("%+v %v",r,err)}
}
func TestUnchangedExposureAndDenial(t *testing.T){
 for _,v:=range []struct{exposed bool;expected string}{{true,"unchanged_exposure_in_lab"},{false,"unchanged_denial_in_lab"}}{
  pub,p:=pair(t,v.exposed,v.exposed,false)
  r,err:=Compare(pub,p)
  if err!=nil||r.Outcome!=v.expected{t.Fatalf("%+v %v",r,err)}
 }
}
func TestInconclusiveOwnerControl(t *testing.T){
 pub,p:=pair(t,true,false,true)
 r,err:=Compare(pub,p)
 if err!=nil||r.Outcome!="inconclusive"{t.Fatalf("%+v %v",r,err)}
}
func TestRejectSameRun(t *testing.T){
 pub,p:=pair(t,true,false,false)
 p.AfterPlan.RunID=p.BeforePlan.RunID
 if _,err:=Compare(pub,p);err==nil{t.Fatal("same-run replay accepted")}
}
func TestRejectDifferentCase(t *testing.T){
 pub,p:=pair(t,true,false,false)
 p.AfterPlan.CaseID="unrelated_case"
 if _,err:=Compare(pub,p);err==nil{t.Fatal("different-case report accepted")}
}
func TestRejectWrongKey(t *testing.T){
 _,p:=pair(t,true,false,false)
 wrong,_,_:=bunnyreceipt.Keypair()
 if _,err:=Compare(wrong,p);err==nil{t.Fatal("wrong signer accepted")}
}
func TestRejectTamperedSignedEvidence(t *testing.T){
 pub,p:=pair(t,true,false,false)
 p.AfterCapture.CrossUserBundle.Receipts[0].Observation.MarkerPresent=true
 if _,err:=Compare(pub,p);err==nil{t.Fatal("altered evidence was accepted")}
}
func TestNoSecretsOrRawMarkerInOutput(t *testing.T){
 pub,p:=pair(t,true,false,false)
 r,err:=Compare(pub,p);if err!=nil{t.Fatal(err)}
 b,err:=json.Marshal(r);if err!=nil{t.Fatal(err)}
 for _,secret:=range []string{owner,foreign,marker}{
  if strings.Contains(string(b),secret){t.Fatal("sensitive test data in summary")}
 }
}
