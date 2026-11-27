package bunnyauthz

import (
 "context"
 "crypto/ed25519"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"

 "github.com/enowdev/antares/internal/bunnyreceipt"
)
const ownerToken="synthetic_OWNER_test_session_012345"
const foreignToken="synthetic_FOREIGN_test_session_789012"
const marker="SYNTHETIC_OWNER_PRIVATE_MARKER"
func setupFixture(t *testing.T,vulnerable bool,denyOwner bool)(Plan,*httptest.Server,*atomic.Int32){
 t.Helper()
 seen:=&atomic.Int32{}
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  seen.Add(1)
  if r.Method!="GET"||r.URL.Path!="/accounts/owner"{w.WriteHeader(405);return}
  auth:=r.Header.Get("Authorization")
  if auth==""{w.WriteHeader(401);return}
  if auth=="Bearer "+ownerToken&&!denyOwner{
   _,_ =w.Write([]byte(marker));return
  }
  if auth=="Bearer "+foreignToken&&vulnerable{
   _,_=w.Write([]byte(marker));return
  }
  w.WriteHeader(403)
 }))
 t.Cleanup(srv.Close)
 p:=Plan{EngagementID:"local_auth_lab",RunID:"run_1",CaseID:"owner_record",
  Origin:srv.URL,ResourcePath:"/accounts/owner",Marker:marker}
 return p,srv,seen
}
func run(t *testing.T,vulnerable bool,denyOwner bool)(ed25519.PublicKey,Plan,Capture){
 t.Helper();p,_,_:=setupFixture(t,vulnerable,denyOwner)
 pub,priv,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)}
 capture,err:=Record(context.Background(),p,priv,Tokens{Owner:ownerToken,Foreign:foreignToken})
 if err!=nil{t.Fatal(err)}
 return pub,p,capture
}
func TestCrossUserExposureInDeliberatelyVulnerableFixture(t *testing.T){
 pub,p,c:=run(t,true,false)
 out,err:=Assess(pub,p,c)
 if err!=nil||out.Outcome!="cross_persona_marker_observed_in_lab"||!out.OwnerAccessObserved||!out.ForeignMarkerObserved||
 out.SignedSamples!=8{t.Fatalf("%+v %v",out,err)}
}
func TestSecureFixtureDeniesCrossUser(t *testing.T){
 pub,p,c:=run(t,false,false)
 out,err:=Assess(pub,p,c)
 if err!=nil||out.Outcome!="cross_persona_denied_in_lab"||out.ForeignMarkerObserved||
 !out.ForeignDeniedObserved{t.Fatalf("%+v %v",out,err)}
}
func TestDeniedOwnerMakesResultInconclusive(t *testing.T){
 pub,p,c:=run(t,false,true)
 out,err:=Assess(pub,p,c)
 if err!=nil||out.Outcome!="inconclusive"{t.Fatalf("%+v %v",out,err)}
}
func TestSameSessionTokenRejected(t *testing.T){
 p,_,count:=setupFixture(t,true,false)
 _,priv,_:=bunnyreceipt.Keypair()
 _,err:=Record(context.Background(),p,priv,Tokens{Owner:ownerToken,Foreign:ownerToken})
 if err==nil||count.Load()!=0{t.Fatal("identical tokens should fail before sending traffic")}
}
func TestOutsideLoopbackRejected(t *testing.T){
 p,_,count:=setupFixture(t,true,false)
 p.Origin="http://example.org:80"
 _,priv,_:=bunnyreceipt.Keypair()
 if _,err:=Record(context.Background(),p,priv,Tokens{Owner:ownerToken,Foreign:foreignToken});err==nil||count.Load()!=0{t.Fatal("external target not rejected")}
}
func TestCrossRunReceiptRejected(t *testing.T){
 pub,p,c:=run(t,true,false)
 p.RunID="another_run"
 if _,err:=Assess(pub,p,c);err==nil{t.Fatal("cross-run data accepted")}
}
func TestWrongKeyRejected(t *testing.T){
 _,p,c:=run(t,true,false)
 wrong,_,_:=bunnyreceipt.Keypair()
 if _,err:=Assess(wrong,p,c);err==nil{t.Fatal("wrong signer accepted")}
}
func TestTamperedRoleRejected(t *testing.T){
 pub,p,c:=run(t,true,false)
 c.CrossUserBundle.Receipts[0].Observation.Actor=OwnerActor
 if _,err:=Assess(pub,p,c);err==nil{t.Fatal("tampered signed role accepted")}
}
func TestTokenNotInReceiptsOrResult(t *testing.T){
 pub,p,c:=run(t,true,false)
 out,err:=Assess(pub,p,c);if err!=nil{t.Fatal(err)}
 raw,_:=json.Marshal(c)
 summary,_:=SummaryJSON(out)
 for _,s:=range []string{ownerToken,foreignToken,marker}{
  if strings.Contains(string(raw),s)||strings.Contains(string(summary),s){t.Fatalf("unredacted content %s",s)}
 }
}
func TestInvalidPathRejected(t *testing.T){
 p,_,count:=setupFixture(t,false,false)
 p.ResourcePath="//example.org/foreign"
 _,priv,_:=bunnyreceipt.Keypair()
 if _,err:=Record(context.Background(),p,priv,Tokens{Owner:ownerToken,Foreign:foreignToken});err==nil||count.Load()!=0{t.Fatal("scheme-relative path allowed")}
}
func TestAnonymousControlsExplicit(t *testing.T){
 pub,p,c:=run(t,true,false)
 for _,bundle:=range []struct{label string;items []bunnyreceipt.Signed}{
  {"owner",c.OwnerBundle.Receipts},{"cross",c.CrossUserBundle.Receipts},
 }{
  for _,receipt:=range bundle.items{
   if receipt.Observation.Kind=="control"&&receipt.Observation.Actor!=AnonymousActor{t.Fatalf("missing anonymous control in %s",bundle.label)}
  }
 }
 if _,err:=Assess(pub,p,c);err!=nil{t.Fatal(err)}
}
