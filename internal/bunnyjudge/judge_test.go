package bunnyjudge

import (
 "encoding/base64"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/enowdev/antares/internal/bunnyaudit"
 "github.com/enowdev/antares/internal/bunnyartifact"
)

func testBundle(t *testing.T,broken bool)(string,[]byte){
 t.Helper()
 dir:=filepath.Join(t.TempDir(),"judge01")
 if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
 key:=[]byte(strings.Repeat("K",32))
 cases:=[]Case{
  {SampleID:"c1",Kind:"candidate",Persona:"owner",Method:"GET",Path:"/candidate"},
  {SampleID:"n1",Kind:"control",Persona:"peer",Method:"GET",Path:"/control"},
  {SampleID:"c2",Kind:"candidate",Persona:"owner",Method:"GET",Path:"/candidate"},
  {SampleID:"n2",Kind:"control",Persona:"peer",Method:"GET",Path:"/control"},
 }
 plan:=Plan{EngagementID:"local_judge",RunID:"judge01",Marker:"PROOF_MARKER",Cases:cases}
 planRaw,_:=json.Marshal(plan)
 trace:=Transcript{Version:1,EngagementID:plan.EngagementID,RunID:plan.RunID}
 for i,c:=range cases{
  body:="ordinary response"
  marker:=c.Kind=="candidate"
  if marker{body="private lab response PROOF_MARKER"}
  if broken&&i==2{marker=false}
  request:=[]byte("GET "+c.Path+" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
  response:=[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"+body)
  trace.Observations=append(trace.Observations,Sample{
   SampleID:c.SampleID,Kind:c.Kind,Persona:c.Persona,Status:200,ObservedAt:time.Now().UTC().Format(time.RFC3339),
   RequestSHA256:digest(request),ResponseSHA256:digest(response),ContentSHA256:digest([]byte(body)),
   MarkerPresent:marker,RequestB64:base64.StdEncoding.EncodeToString(request),
   ResponseB64:base64.StdEncoding.EncodeToString(response),
  })
 }
 raw,_:=json.Marshal(trace)
 source:=[]byte("print('synthetic reviewed fixture')\n")
 validation,_:=json.Marshal(map[string]any{
  "engagement_id":plan.EngagementID,"run_id":plan.RunID,
  "script_sha256":digest(source),"plan_sha256":digest(planRaw),
  "raw_evidence_file":"transcript.enc","raw_evidence_sha256":digest(raw),
 })
 for name,data:=range map[string][]byte{
  "scenario.py":source,"plan.json":planRaw,"validation.json":validation,
  "report.md":[]byte("# synthetic test\n"),"README.txt":[]byte("Synthetic evidence\n"),
 }{
  if err:=os.WriteFile(filepath.Join(dir,name),data,0600);err!=nil{t.Fatal(err)}
 }
 if _,err:=bunnyartifact.Store(dir,"transcript","http_proof",raw,key);err!=nil{t.Fatal(err)}
 if _,err:=bunnyaudit.SealRun(dir,key);err!=nil{t.Fatal(err)}
 return dir,key
}
func TestJudgeRechecksEncryptedTranscriptAndControls(t *testing.T){
 dir,key:=testBundle(t,false)
 verdict,err:=JudgeRun(dir,key)
 if err!=nil{t.Fatal(err)}
 if verdict.Classification!="replicated_observation_needs_independent_impact_review"||
  verdict.ValidCandidates!=2||verdict.ValidControls!=2||verdict.ImpactVerified{
  t.Fatalf("unexpected independent judge: %+v",verdict)
 }
 b,_:=json.Marshal(verdict)
 if strings.Contains(string(b),"PROOF_MARKER")||strings.Contains(string(b),"private lab response"){
  t.Fatal("judge leaked response contents")
 }
}
func TestRejectTamperedReportOrWrongKey(t *testing.T){
 dir,key:=testBundle(t,false)
 if _,err:=JudgeRun(dir,[]byte(strings.Repeat("X",32)));err==nil{t.Fatal("wrong key accepted")}
 if err:=os.WriteFile(filepath.Join(dir,"report.md"),[]byte("tampered\n"),0600);err!=nil{t.Fatal(err)}
 if _,err:=JudgeRun(dir,key);err==nil{t.Fatal("tampered report verified")}
}
func TestDisagreeWithFalseReportedMarker(t *testing.T){
 dir,key:=testBundle(t,true)
 if _,err:=JudgeRun(dir,key);err==nil{
  t.Fatal("contradictory model-generated marker assertion was accepted")
 }
}
