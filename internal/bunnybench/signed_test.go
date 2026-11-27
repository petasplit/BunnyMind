package bunnybench

import (
 "crypto/ed25519"
 "strings"
 "testing"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)
func mkBundle(t *testing.T,priv ed25519.PrivateKey,run,caseID string,hasControls bool)bunnyreceipt.Bundle{
 t.Helper()
 b:=bunnyreceipt.Bundle{EngagementID:"lab_1",RunID:run,CaseID:caseID}
 ids:=[]string{"p1","p2"}
 if hasControls{ids=append(ids,"c1","c2")}
 for _,id:=range ids{
  positive:=id[0]=='p'
  kind:="control";if positive{kind="positive"}
  o:=bunnyreceipt.Observation{
   Version:1,EngagementID:"lab_1",RunID:run,CaseID:caseID,SampleID:id,
   Kind:kind,Method:"GET",Origin:"http://127.0.0.1:8765",
   RequestSHA256:bunnyreceipt.Dig("req:"+run+caseID+id),
   ResponseSHA256:bunnyreceipt.Dig("res:"+run+caseID+id),
   MarkerSHA256:bunnyreceipt.Dig("marker"),ResponseStatus:200,
   MarkerPresent:positive,RecordedAt:"2026-11-27T10:00:00Z",
  }
  receipt,err:=bunnyreceipt.Sign(priv,o)
  if err!=nil{t.Fatal(err)}
  b.Receipts=append(b.Receipts,receipt)
 }
 return b
}
func signedFixture(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey,SignedStudy){
 t.Helper();pub,priv,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)}
 s:=SignedStudy{EngagementID:"lab_1",Manifest:Manifest{Benchmark:"lab-suite",Cases:[]Case{{ID:"C1"},{ID:"C2"}}},
 Trials:[]SignedTrial{{RunID:"run_a",Model:"test-model",Reported:[]string{"C1","C2"}}}}
 s.Trials[0].Bundles=[]bunnyreceipt.Bundle{mkBundle(t,priv,"run_a","C1",true)}
 return pub,priv,s
}
func TestSignedScoring(t *testing.T){
 pub,_,s:=signedFixture(t)
 result,err:=ScoreSignedStudy(pub,s);if err!=nil{t.Fatal(err)}
 sc:=result.Trials[0]
 if sc.SupportedCount!=1||sc.Recall!=0.5||sc.Precision!=0.5{t.Fatalf("%+v",sc)}
}
func TestReportedButUnsignedIsUnsupported(t *testing.T){
 pub,_,s:=signedFixture(t);s.Trials[0].Bundles=nil
 result,err:=ScoreSignedStudy(pub,s);if err!=nil{t.Fatal(err)}
 if result.Trials[0].SupportedCount!=0||result.Trials[0].FalseOrUnsupportedCount!=2{t.Fatal("unattested claims counted")}
}
func TestTamperedBundleRejected(t *testing.T){
 pub,_,s:=signedFixture(t)
 s.Trials[0].Bundles[0].Receipts[0].Observation.MarkerPresent=false
 if _,err:=ScoreSignedStudy(pub,s);err==nil{t.Fatal("tampered receipt counted")}
}
func TestCrossTrialRejected(t *testing.T){
 pub,_,s:=signedFixture(t);s.Trials[0].Bundles[0].RunID="run_b"
 if _,err:=ScoreSignedStudy(pub,s);err==nil{t.Fatal("cross-trial accepted")}
}
func TestUnknownCaseRejected(t *testing.T){
 pub,priv,s:=signedFixture(t)
 s.Trials[0].Bundles=[]bunnyreceipt.Bundle{mkBundle(t,priv,"run_a","UNKNOWN",true)}
 if _,err:=ScoreSignedStudy(pub,s);err==nil{t.Fatal("unknown case credited")}
}
func TestWithoutControlsNotCredited(t *testing.T){
 pub,priv,s:=signedFixture(t)
 s.Trials[0].Bundles[0]=mkBundle(t,priv,"run_a","C1",false)
 result,err:=ScoreSignedStudy(pub,s);if err!=nil{t.Fatal(err)}
 if result.Trials[0].SupportedCount!=0{t.Fatal("no-control case credited")}
}
func TestWrongKeyRejected(t *testing.T){
 _,_,s:=signedFixture(t);other,_,_:=bunnyreceipt.Keypair()
 if _,err:=ScoreSignedStudy(other,s);err==nil{t.Fatal("wrong signer accepted")}
}
func TestDuplicateBundleRejected(t *testing.T){
 pub,_,s:=signedFixture(t)
 s.Trials[0].Bundles=append(s.Trials[0].Bundles,s.Trials[0].Bundles[0])
 if _,err:=ScoreSignedStudy(pub,s);err==nil{t.Fatal("duplicate bundle inflated score")}
}
func TestModelAggregation(t *testing.T){
 pub,priv,s:=signedFixture(t)
 s.Trials=append(s.Trials,SignedTrial{RunID:"run_b",Model:"second-model",Reported:[]string{"C1","C2"},
 Bundles:[]bunnyreceipt.Bundle{mkBundle(t,priv,"run_b","C1",true),mkBundle(t,priv,"run_b","C2",true)}})
 result,err:=ScoreSignedStudy(pub,s);if err!=nil{t.Fatal(err)}
 if len(result.Models)!=2{t.Fatalf("expected two models: %+v",result.Models)}
 found:=false
 for _,model:=range result.Models{
  if model.Model=="second-model"{found=true;if model.MeanRecall!=1{t.Fatalf("wrong second-model recall: %+v",model)}}
 }
 if !found{t.Fatal("second model missing")}
 if !strings.Contains(result.Disclaimer,"signatures"){t.Fatal("missing provenance disclaimer")}
}
