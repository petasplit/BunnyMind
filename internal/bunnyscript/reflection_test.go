package bunnyscript

import (
 "context"
 "crypto/rand"
 "net/http"
 "net/http/httptest"
 "os/exec"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
)
// A marker echoed from the *request* is not evidence that the application
// generated that marker independently. Reflections must fail the proof gate.
func TestPythonReflectionNeverPassesOracle(t *testing.T){
 python,err:=exec.LookPath("python3")
 if err!=nil{python,err=exec.LookPath("python")}
 if err!=nil{t.Skip("Python 3 unavailable")}
 marker:="CONTROLLED-ECHO-ONLY-93211"
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if strings.HasPrefix(r.URL.Path,"/echo"){
   _,_=w.Write([]byte(r.URL.Query().Get("value")))
  }else{
   w.WriteHeader(http.StatusForbidden)
   _,_=w.Write([]byte("denied"))
  }
 }))
 defer server.Close()
 plan:=Plan{EngagementID:"reflection-check",RunID:"reflect-check01",
  Origin:server.URL,Marker:marker,
  Cases:[]Case{
   {SampleID:"positive1",Kind:"candidate",Method:"GET",Path:"/echo?value="+marker},
   {SampleID:"control1",Kind:"control",Method:"GET",Path:"/denied"},
   {SampleID:"positive2",Kind:"candidate",Method:"GET",Path:"/echo?value="+marker},
   {SampleID:"control2",Kind:"control",Method:"GET",Path:"/denied"},
  }}
 policy:=bunnyguard.Policy{EngagementID:plan.EngagementID,AllowedOrigins:[]string{server.URL},
  AllowedMethods:[]string{"GET"},MaxNetworkCalls:12}
 key:=make([]byte,32);_,_=rand.Read(key)
 summary,err:=(Runner{Python:python,Root:t.TempDir(),EncryptionKey:key}).Run(context.Background(),plan,policy)
 if err!=nil{t.Fatal(err)}
 if summary.Outcome=="repeated_candidate_with_negative_controls"{
  t.Fatal("request reflection was incorrectly accepted as a validated candidate signal")
 }
 for _,r:=range summary.Receipts{
  if r.Kind=="candidate"&&(!r.MarkerPresent||!r.MarkerInRequest){
   t.Fatalf("reflection not accounted for: %+v",r)
  }
 }
}
