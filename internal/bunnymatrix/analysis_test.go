package bunnymatrix

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "strings"
 "testing"
)

func h(s string) string {
 v:=sha256.Sum256([]byte(s))
 return hex.EncodeToString(v[:])
}
func sample(id,actor,signal string,status int) Observation {
 o:=Observation{
  ID:id,CaseID:"case-A",EndpointID:"ep_42",ResourceSHA256:h("owned fixture 42"),
  OwnerID:"user_A",ActorID:actor,Method:"GET",Status:status,MarkerSignal:signal,
  EvidenceSHA256:h("receipt:"+id),Source:"synthetic_fixture",
 }
 if signal=="present" {o.MarkerSHA256=h("harmless fixture marker")}
 return o
}
func mustAnalyze(t *testing.T,obs ...Observation) Report{
 t.Helper()
 r,err:=Analyze(obs)
 if err!=nil {t.Fatal(err)}
 return r
}
func TestCandidateNeedsExplicitResourceMarker(t *testing.T){
 r:=mustAnalyze(t,sample("owner","user_A","present",200),sample("peer","user_B","present",200),sample("anon","anonymous","absent",403))
 if r.TotalCases!=1||r.Cases[0].Status!="cross_identity_candidate"||!r.Cases[0].NeedsIndependentReproduction {
  t.Fatalf("unexpected candidate: %+v",r)
 }
 if !r.Cases[0].HasDeniedAnonymousControl{t.Fatalf("missing negative control: %+v",r.Cases[0])}
}
func TestRepeatedCandidateRequiresIndependentEvidence(t *testing.T){
 r:=mustAnalyze(t,sample("owner1","user_A","present",200),sample("owner2","user_A","present",200),
 sample("peer1","user_B","present",200),sample("peer2","user_B","present",200),
 sample("anon","anonymous","absent",401))
 if r.Cases[0].Status!="repeated_cross_identity_candidate"{t.Fatalf("expected repeated candidate: %+v",r.Cases[0])}
}
func TestAccessDeniedAndUncertainResults(t *testing.T){
 denied:=mustAnalyze(t,sample("owner","user_A","present",200),sample("peer","user_B","absent",403))
 if denied.Cases[0].Status!="peer_access_denied"||denied.Cases[0].NeedsIndependentReproduction {
  t.Fatalf("unexpected denied outcome: %+v",denied.Cases[0])
 }
 unknown:=mustAnalyze(t,sample("owner","user_A","present",200),sample("peer","user_B","unknown",200))
 if unknown.Cases[0].Status!="inconclusive"{t.Fatalf("2xx without marker mistaken for access: %+v",unknown.Cases[0])}
}
func TestAnonymousCandidateAndMissingControls(t *testing.T){
 r:=mustAnalyze(t,sample("owner","user_A","present",200),sample("anon","anonymous","present",200))
 if r.Cases[0].Status!="anonymous_resource_access_candidate" {t.Fatalf("wrong anonymous classification: %+v",r.Cases[0])}
 missing:=mustAnalyze(t,sample("owner","user_A","present",200))
 if missing.Cases[0].Status!="peer_control_missing" {t.Fatalf("missing peer not detected: %+v",missing.Cases[0])}
 baseline:=mustAnalyze(t,sample("owner","user_A","unknown",200),sample("peer","user_B","present",200))
 if baseline.Cases[0].Status!="owner_baseline_missing" {t.Fatalf("missing owner marker not detected: %+v",baseline.Cases[0])}
}
func TestRejectInvalidOrSensitiveMetadata(t *testing.T){
 o:=sample("normal","user_A","present",200)
 variants:=[]Observation{}
 bad:=o;bad.ID="user:secret@example.com";variants=append(variants,bad)
 bad=o;bad.ActorID="Bearer token";variants=append(variants,bad)
 bad=o;bad.ResourceSHA256="foo";variants=append(variants,bad)
 bad=o;bad.MarkerSHA256="";variants=append(variants,bad)
 bad=o;bad.Source="model_verified";variants=append(variants,bad)
 bad=o;bad.Status=999;variants=append(variants,bad)
 bad=o;bad.OwnerID="anonymous";variants=append(variants,bad)
 bad=o;bad.MarkerSignal="absent";variants=append(variants,bad)
 bad=o;bad.Method="DELETE";variants=append(variants,bad)
 for i,x:=range variants {
  if _,err:=Analyze([]Observation{x});err==nil{t.Fatalf("accepted invalid observation %d: %+v",i,x)}
 }
 if _,err:=Analyze([]Observation{o,o});err==nil {t.Fatal("accepted duplicate observation ID")}
 mismatch:=sample("peer","user_B","present",200)
 mismatch.OwnerID="user_C"
 if _,err:=Analyze([]Observation{o,mismatch});err==nil{t.Fatal("accepted inconsistent resource owner")}
}
func TestNoRawSecretsAndDeterminism(t *testing.T){
 o:=sample("owner","user_A","present",200)
 p:=sample("peer","user_B","present",200)
 a:=mustAnalyze(t,p,o)
 b:=mustAnalyze(t,o,p)
 ja,_:=json.Marshal(a);jb,_:=json.Marshal(b)
 if string(ja)!=string(jb){t.Fatalf("non-deterministic comparison\n%s\n%s",ja,jb)}
 for _,secret:=range []string{"Bearer ","password","/private/","?token="}{
  if strings.Contains(string(ja),secret){t.Fatalf("sensitive string appeared: %s",secret)}
 }
}
