package bunnylab

import (
 "context"
 "crypto/ed25519"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"

 "github.com/enowdev/antares/internal/bunnyreceipt"
)
func planFor(origin string)Plan{
 return Plan{
  EngagementID:"local_lab",RunID:"run_01",CaseID:"case_01",
  Origin:origin,Marker:"SYNTHETIC_PROOF_123",
  Probes:[]Probe{
   {SampleID:"p1",Kind:"positive",Path:"/positive"},
   {SampleID:"c1",Kind:"control",Path:"/control"},
   {SampleID:"p2",Kind:"positive",Path:"/positive"},
   {SampleID:"c2",Kind:"control",Path:"/control"},
  },
 }
}
func signer(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper();pub,priv,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)};return pub,priv
}
func TestCaptureAndVerifyLocalFixture(t *testing.T){
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path=="/positive"{_,_=w.Write([]byte("SYNTHETIC_PROOF_123"))}else{w.WriteHeader(403);_,_=w.Write([]byte("denied"))}
 }))
 defer server.Close()
 pub,priv:=signer(t)
 bundle,err:=Capture(context.Background(),planFor(server.URL),priv)
 if err!=nil{t.Fatal(err)}
 result,err:=bunnyreceipt.Verify(pub,bundle)
 if err!=nil||result.Assessment!="consistent-signed-observations"{t.Fatalf("result %+v err %v",result,err)}
 if bundle.Receipts[1].Observation.ResponseStatus!=403{t.Fatal("control status wrong")}
}
func TestNoExternalTargets(t *testing.T){
 for _,host:=range []string{"https://example.org:443","http://169.254.169.254:80","http://localhost:8000","http://10.1.2.3:99","file:///tmp/lab"}{
  if err:=Validate(planFor(host));err==nil{t.Fatalf("allowed %s",host)}
 }
}
func TestRedirectionDoesNotLeaveLoopback(t *testing.T){
 var hits atomic.Int32
 target:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){hits.Add(1)}));defer target.Close()
 source:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){http.Redirect(w,r,target.URL+"/outside",302)}));defer source.Close()
 _,priv:=signer(t)
 if _,err:=Capture(context.Background(),planFor(source.URL),priv);err==nil{t.Fatal("redirect accepted")}
 if hits.Load()!=0{t.Fatal("redirect followed")}
}
func TestTooLargeResponseRejected(t *testing.T){
 s:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){_,_=w.Write([]byte(strings.Repeat("A",MaxBody+2)))}));defer s.Close()
 _,priv:=signer(t)
 if _,err:=Capture(context.Background(),planFor(s.URL),priv);err==nil{t.Fatal("large response accepted")}
}
func TestMissingControlsRejected(t *testing.T){
 p:=planFor("http://127.0.0.1:8030")
 p.Probes=[]Probe{{SampleID:"a",Kind:"positive",Path:"/ok"},{SampleID:"b",Kind:"positive",Path:"/ok"},{SampleID:"c",Kind:"positive",Path:"/ok"},{SampleID:"d",Kind:"positive",Path:"/ok"}}
 if Validate(p)==nil{t.Fatal("control-free plan allowed")}
}
func TestDuplicateIDRejected(t *testing.T){
 p:=planFor("http://127.0.0.1:8030")
 p.Probes[1].SampleID="p1"
 if Validate(p)==nil{t.Fatal("duplicate sample accepted")}
}
func TestCrossHostPathRejected(t *testing.T){
 p:=planFor("http://127.0.0.1:8030")
 p.Probes[0].Path="//example.org/evil"
 if Validate(p)==nil{t.Fatal("scheme-relative path accepted")}
}
func TestReflectionNotCredited(t *testing.T){
 s:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){_,_=w.Write([]byte("SYNTHETIC_PROOF_123"))}));defer s.Close()
 p:=planFor(s.URL);p.Probes[0].Path="/positive?q=SYNTHETIC_PROOF_123"
 pub,priv:=signer(t)
 bundle,err:=Capture(context.Background(),p,priv)
 if err!=nil{t.Fatal(err)}
 summary,err:=bunnyreceipt.Verify(pub,bundle)
 if err!=nil||summary.Assessment!="inconclusive"{t.Fatalf("%+v %v",summary,err)}
}
func TestNoBodyOrRequestInSignedReceipts(t *testing.T){
 s:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){_,_=w.Write([]byte("SYNTHETIC_PROOF_123"))}));defer s.Close()
 _,priv:=signer(t)
 bundle,err:=Capture(context.Background(),planFor(s.URL),priv)
 if err!=nil{t.Fatal(err)}
 for _,receipt:=range bundle.Receipts{
  if receipt.Observation.ResponseSHA256==""||receipt.Observation.RequestSHA256==""{t.Fatal("missing hashes")}
  if strings.Contains(receipt.Signature,"SYNTHETIC_PROOF_123"){t.Fatal("raw marker emitted")}
 }
}
