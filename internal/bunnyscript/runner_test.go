package bunnyscript

import (
 "context"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"
 
 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnyguard"
)
func scriptFixture(t *testing.T)(Plan,bunnyguard.Policy,func()){
 t.Helper()
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/plain")
  if strings.HasPrefix(r.URL.Path,"/candidate"){
   _,_=w.Write([]byte("marker BUNNY-SAFE-OWNED-PROOF"))
  }else{
   w.WriteHeader(http.StatusForbidden)
   _,_=w.Write([]byte("control denied"))
  }
 }))
 p:=Plan{EngagementID:"approved-proof",RunID:"proof-0001",Origin:server.URL,
  Marker:"BUNNY-SAFE-OWNED-PROOF",Cases:[]Case{
   {SampleID:"candidate-a",Kind:"candidate",Method:"GET",Path:"/candidate/a"},
   {SampleID:"control-a",Kind:"control",Method:"GET",Path:"/control/a"},
   {SampleID:"candidate-b",Kind:"candidate",Method:"GET",Path:"/candidate/b"},
   {SampleID:"control-b",Kind:"control",Method:"GET",Path:"/control/b"},
  }}
 policy:=bunnyguard.Policy{EngagementID:"approved-proof",AllowedOrigins:[]string{server.URL},
  AllowedMethods:[]string{"GET","HEAD"},MaxNetworkCalls:24}
 return p,policy,server.Close
}
func TestGeneratedScriptExecutableAndFullProofSaved(t *testing.T){
 python,err:=exec.LookPath("python3")
 if err!=nil{python,err=exec.LookPath("python")}
 if err!=nil{t.Skip("Python 3 interpreter not installed")}
 p,policy,closeFixture:=scriptFixture(t)
 defer closeFixture()
 key:=make([]byte,32);_,_=rand.Read(key)
 root:=t.TempDir()
 summary,err:=(Runner{Root:root,Python:python,EncryptionKey:key}).Run(context.Background(),p,policy)
 if err!=nil{t.Fatal(err)}
 if summary.Outcome!="repeated_candidate_with_negative_controls"||
 summary.ConsistentCandidates!=2||summary.ConsistentControls!=2{
  t.Fatalf("unexpected proof assessment: %+v",summary)
 }
 dir:=filepath.Join(root,p.RunID)
 script,err:=os.ReadFile(filepath.Join(dir,"scenario.py"))
 if err!=nil||SHA(script)!=summary.ScriptSHA256||!strings.Contains(string(script),"candidate-a"){
  t.Fatalf("generated scenario missing or mismatched: %v",err)
 }
 if _,err:=os.Stat(filepath.Join(dir,"_unencrypted_capture.json"));!os.IsNotExist(err){
  t.Fatal("private plaintext intermediate transcript still present")
 }
 encrypted,err:=os.ReadFile(filepath.Join(dir,summary.RawEvidenceFile))
 if err!=nil||strings.Contains(string(encrypted),"BUNNY-SAFE-OWNED-PROOF"){
  t.Fatal("raw proof exposed outside encrypted vault")
 }
 raw,err:=bunnyartifact.Open(dir,"transcript","http_proof",key)
 if err!=nil||SHA(raw)!=summary.RawEvidenceSHA256{t.Fatalf("raw proof decryption invalid %v",err)}
 var traceData trace
 if err:=json.Unmarshal(raw,&traceData);err!=nil{t.Fatal(err)}
 if len(traceData.Observations)!=4{t.Fatal("missing captured request/response pairs")}
 for _,obs:=range traceData.Observations{
  requestBytes,_:=base64.StdEncoding.DecodeString(obs.RequestB64)
  responseBytes,_:=base64.StdEncoding.DecodeString(obs.ResponseB64)
  if !strings.Contains(string(requestBytes),"User-Agent: BunnyMind-Python-Evidence")||
    !strings.Contains(string(responseBytes),"HTTP/1.1"){
   t.Fatalf("capture omitted HTTP metadata: %+v",obs)
  }
 }
}
func TestProofPlanRejectsUnapprovedOriginAndUnsafeActions(t *testing.T){
 p,policy,closeFixture:=scriptFixture(t)
 defer closeFixture()
 if err:=Validate(p,policy);err!=nil{t.Fatal(err)}
 bad:=p;bad.Origin="https://other.example"
 if err:=Validate(bad,policy);err==nil{t.Fatal("out-of-scope site allowed")}
 bad=p;bad.Cases=append([]Case(nil),p.Cases...);bad.Cases[0].Method="DELETE"
 if err:=Validate(bad,policy);err==nil{t.Fatal("destructive action allowed")}
 bad=p;bad.Cases=append([]Case(nil),p.Cases...);bad.Cases[0].Path="//169.254.169.254/metadata"
 if err:=Validate(bad,policy);err==nil{t.Fatal("scheme-relative metadata endpoint allowed")}
 bad=p;bad.Cases=append([]Case(nil),p.Cases...);bad.Cases[0].Path="/%2e%2e/admin"
 if err:=Validate(bad,policy);err==nil{t.Fatal("escaped traversal allowed")}
 bad=p;bad.Cases=p.Cases[:2]
 if err:=Validate(bad,policy);err==nil{t.Fatal("negative controls missing")}
 bad=p;bad.MinIntervalMS=0;policy.MinIntervalMS=100
 if err:=Validate(bad,policy);err==nil{t.Fatal("engagement pacing weakened")}
}
func TestSourceGenerationDeterministicAndNoCodeFromWeb(t *testing.T){
 p,policy,closeFixture:=scriptFixture(t);defer closeFixture()
 if err:=Validate(p,policy);err!=nil{t.Fatal(err)}
 a,e:=Generate(p);if e!=nil{t.Fatal(e)}
 b,e:=Generate(p);if e!=nil{t.Fatal(e)}
 if SHA(a)!=SHA(b){t.Fatal("scripts differed for same approved scenario")}
 if !strings.Contains(string(a),"candidate-b")||!strings.Contains(string(a),"GET"){
  t.Fatal("generated source did not reflect test case plan")
 }
}
