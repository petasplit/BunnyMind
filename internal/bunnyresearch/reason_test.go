package bunnyresearch

import (
 "crypto/sha256"
 "encoding/hex"
 "strings"
 "testing"
)
func sha(v string)string{h:=sha256.Sum256([]byte(v));return hex.EncodeToString(h[:])}
func o(id,role,signal,treatment string)Observation{
 return Observation{ID:id,Role:role,Signal:signal,TreatmentSHA256:sha(treatment),EvidenceSHA256:sha("evidence:"+id)}
}
func study()Study{return Study{CaseID:"AUTH_CASE",Kind:"authorization",Budget:16,
 Observations:[]Observation{o("b","baseline","normal","baseline"),o("c","control","denied","control")}}}
func TestNeedBaseline(t *testing.T){
 s:=study();s.Observations=nil
 d,err:=Analyze(s);if err!=nil||d.NextAction!="collect_baseline"{t.Fatalf("%+v %v",d,err)}
}
func TestMissingControls(t *testing.T){
 s:=study();s.Observations=s.Observations[:1]
 d,err:=Analyze(s);if err!=nil||d.NextAction!="collect_negative_control"{t.Fatalf("%+v %v",d,err)}
}
func TestBlockIsNotDisproof(t *testing.T){
 s:=study();s.Observations=append(s.Observations,o("x","candidate","intermediary_block","attempt"))
 d,err:=Analyze(s)
 if err!=nil||d.Classification!="intermediary_blocked_not_tested"||d.NextAction!="classify_intermediary_response"{
  t.Fatalf("%+v %v",d,err)
 }
}
func TestControlWithMarkerStops(t *testing.T){
 s:=study();s.Observations[1].Signal="marker"
 d,err:=Analyze(s)
 if err!=nil||d.Classification!="invalid_control"{t.Fatalf("%+v %v",d,err)}
}
func TestNovelReproducibleSignalOnlyProvisional(t *testing.T){
 s:=study()
 s.Observations=append(s.Observations,o("x","candidate","marker","one"),o("y","candidate","marker","one"))
 d,err:=Analyze(s)
 if err!=nil||d.NextAction!="request_independent_reproduction"||d.Classification!="unverified_candidate_signal"{
  t.Fatalf("%+v %v",d,err)
 }
}
func TestNoPayloadGeneration(t *testing.T){
 v,err:=Canary();if err!=nil{t.Fatal(err)}
 if !strings.HasPrefix(v,"BUNNY_BENIGN_")||len(v)!=len("BUNNY_BENIGN_")+32{t.Fatal("invalid canary")}
 a,_:=Canary()
 if a==v{t.Fatal("unexpected duplicate canary")}
}
func TestDuplicateLowInformation(t *testing.T){
 s:=study()
 for i,n:=range []string{"x","y","z"}{s.Observations=append(s.Observations,o(n,"candidate","normal","same")) ;_=i}
 d,err:=Analyze(s)
 if err!=nil||d.NextAction!="form_different_hypothesis"||d.RepeatedCandidateTreatments!=2{t.Fatalf("%+v %v",d,err)}
}
func TestBudgetHardStop(t *testing.T){
 s:=study();s.Budget=3;s.Observations=append(s.Observations,o("x","candidate","normal","t1"))
 d,err:=Analyze(s)
 if err!=nil||d.NextAction!="stop_and_review_budget"{t.Fatalf("%+v %v",d,err)}
}
func TestDuplicateIDRejected(t *testing.T){
 s:=study();s.Observations=append(s.Observations,o("b","candidate","marker","t"))
 if _,err:=Analyze(s);err==nil{t.Fatal("duplicate samples accepted")}
}
func TestForgedDigestRejected(t *testing.T){
 s:=study();s.Observations[0].EvidenceSHA256="not-sha"
 if _,err:=Analyze(s);err==nil{t.Fatal("malformed evidence digest")}
}
func TestBaselineBlockNotTargetRejection(t *testing.T){
 s:=study();s.Observations[0].Signal="intermediary_block"
 d,err:=Analyze(s)
 if err!=nil||d.NextAction!="diagnose_baseline"{t.Fatalf("%+v %v",d,err)}
}
func TestOneMarkerNeedsControl(t *testing.T){
 s:=study();s.Observations=append(s.Observations,o("x","candidate","marker","t"))
 d,err:=Analyze(s)
 if err!=nil||d.Classification!="single_candidate_signal"{t.Fatalf("%+v %v",d,err)}
}
