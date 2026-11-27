package bunnylab

import (
 "context"
 "net/http"
 "net/http/httptest"
 "testing"

 "github.com/enowdev/antares/internal/bunnybench"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)
// TestCapturedEvidenceScoresEndToEnd connects an observed loopback HTTP
// response to a signed receipt and then to the evidence-gated scorer.
func TestCapturedEvidenceScoresEndToEnd(t *testing.T){
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path=="/positive"{
   w.Header().Set("Content-Type","text/plain")
   _,_=w.Write([]byte("SYNTHETIC_PROOF_123"))
  }else if r.URL.Path=="/control"{
   w.WriteHeader(http.StatusForbidden)
   _,_=w.Write([]byte("No indicator"))
  }else{w.WriteHeader(http.StatusNotFound)}
 }))
 defer srv.Close()
 pub,priv,err:=bunnyreceipt.Keypair()
 if err!=nil{t.Fatal(err)}
 captured,err:=Capture(context.Background(),planFor(srv.URL),priv)
 if err!=nil{t.Fatal(err)}
 study:=bunnybench.SignedStudy{
  EngagementID:"local_lab",
  Manifest:bunnybench.Manifest{Benchmark:"controlled-local-integration",Cases:[]bunnybench.Case{{ID:"case_01"}}},
  Trials:[]bunnybench.SignedTrial{{
   RunID:"run_01",Model:"synthetic-test-not-an-ai-model",
   Reported:[]string{"case_01"},
   Bundles:[]bunnyreceipt.Bundle{captured},
  }},
 }
 scored,err:=bunnybench.ScoreSignedStudy(pub,study)
 if err!=nil{t.Fatal(err)}
 if scored.Trials[0].Precision!=1||scored.Trials[0].Recall!=1{
  t.Fatalf("signed local capture not credited: %+v",scored.Trials[0])
 }
 // Altering the recorder-supplied metadata must invalidate the signature,
 // rather than silently converting manipulated results into benchmark credit.
 study.Trials[0].Bundles[0].Receipts[0].Observation.MarkerPresent=false
 if _,err:=bunnybench.ScoreSignedStudy(pub,study);err==nil{
  t.Fatal("tampered lab observation was accepted")
 }
}
