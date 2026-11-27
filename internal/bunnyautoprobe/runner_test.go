package bunnyautoprobe

import (
 "context"
 "crypto/rand"
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
 "github.com/enowdev/antares/internal/bunnyscript"
)
func controlled(t *testing.T)(Spec,bunnyguard.Policy,func()){
 t.Helper()
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/plain")
  switch r.URL.Path{
  case "/candidate-good":
   _,_=w.Write([]byte("Owned test fixture marker BUNNY-OWNED-SUCCESS"))
  case "/candidate-bad":
   _,_=w.Write([]byte("normal response with no expected marker"))
  default:
   w.WriteHeader(http.StatusForbidden)
   _,_=w.Write([]byte("negative control properly denied"))
  }
 }))
 s:=Spec{EngagementID:"authorized",CampaignID:"adaptive001",
  Origin:server.URL,Marker:"BUNNY-OWNED-SUCCESS",
  CandidatePaths:[]string{"/candidate-bad","/candidate-good"},
  NegativeControlPaths:[]string{"/control"},MaxRounds:4,
  MaxRequests:16,MinIntervalMS:0}
 policy:=bunnyguard.Policy{EngagementID:"authorized",
  AllowedOrigins:[]string{server.URL},AllowedMethods:[]string{"GET","HEAD"},
  MaxNetworkCalls:32,MinIntervalMS:0}
 return s,policy,server.Close
}
func TestAdaptiveProofEscalatesOnlyToRepeatedObservation(t *testing.T){
 python,err:=exec.LookPath("python3")
 if err!=nil{python,err=exec.LookPath("python")}
 if err!=nil{t.Skip("Python not installed")}
 s,policy,closeServer:=controlled(t)
 defer closeServer()
 key:=make([]byte,32);_,_=rand.Read(key)
 out:=t.TempDir()
 campaign,err:=(Runner{Proof:bunnyscript.Runner{
  Python:python,Root:out,EncryptionKey:key,
 }}).Execute(context.Background(),s,policy)
 if err!=nil{t.Fatal(err)}
 if campaign.Outcome!="replicated_observation_unverified"||
  len(campaign.Runs)!=3||campaign.RequestsUsed!=12{
  t.Fatalf("autonomous selection/replication failed: %+v",campaign)
 }
 if campaign.Runs[0].Outcome!="inconclusive_or_failed_control"{
  t.Fatalf("unexpected first failed candidate %+v",campaign.Runs[0])
 }
 if campaign.Runs[1].CandidatePathSHA256!=campaign.Runs[2].CandidatePathSHA256||
   campaign.Runs[1].ScriptSHA256==campaign.Runs[2].ScriptSHA256{
  t.Fatal("expected distinct script sources but matching candidate path across fresh proof rounds")
 }
 folder:=filepath.Join(out,s.CampaignID)
 for _,item:=range campaign.Runs{
  dir:=filepath.Join(folder,item.RunID)
  for _,file:=range []string{"scenario.py","plan.json","validation.json","report.md","transcript.enc"}{
   if _,err:=os.Stat(filepath.Join(dir,file));err!=nil{t.Fatalf("missing %s/%s: %v",item.RunID,file,err)}
  }
  raw,err:=bunnyartifact.Open(dir,"transcript","http_proof",key)
  if err!=nil||bunnyscript.SHA(raw)!=item.EvidenceSHA256{t.Fatal("encrypted transcript not verifiable")}
 }
 report,err:=os.ReadFile(filepath.Join(folder,"report.md"))
 if err!=nil||!strings.Contains(string(report),"not an independently confirmed vulnerability"){
  t.Fatalf("campaign report overclaims findings: %v",err)
 }
 saved,err:=os.ReadFile(filepath.Join(folder,"campaign.json"))
 if err!=nil{t.Fatal(err)}
 var reloaded CampaignResult
 if json.Unmarshal(saved,&reloaded)!=nil||reloaded.Outcome!=campaign.Outcome{
  t.Fatal("campaign evidence was not independently auditable")
 }
}
func TestAdaptivePlanCannotExpandScopeOrBudget(t *testing.T){
 s,policy,closeServer:=controlled(t);defer closeServer()
 if err:=Validate(s,policy);err!=nil{t.Fatal(err)}
 cases:=[]struct{
  name string
  change func(*Spec)
 }{
  {"unapproved origin",func(v *Spec){v.Origin="https://evil.example"}},
  {"private metadata",func(v *Spec){v.CandidatePaths=[]string{"//169.254.169.254/latest"}}},
  {"encoded traversal",func(v *Spec){v.CandidatePaths=[]string{"/%2e%2e/secrets"}}},
  {"repeat request path",func(v *Spec){v.NegativeControlPaths=[]string{"/candidate-bad"}}},
  {"request budget too low",func(v *Spec){v.MaxRequests=8}},
  {"request budget too high",func(v *Spec){v.MaxRequests=97}},
  {"too many rounds",func(v *Spec){v.MaxRounds=9}},
  {"unapproved identity",func(v *Spec){v.CandidatePersona="INVALID/NAME"}},
 }
 for _,tc:=range cases{
  t.Run(tc.name,func(t *testing.T){
   item:=s
   tc.change(&item)
   if err:=Validate(item,policy);err==nil{t.Fatal("unsafe autonomous study accepted")}
  })
 }
}
func TestAdaptiveStopReasonNeverClaimsExploit(t *testing.T){
 s,policy,closeServer:=controlled(t);defer closeServer()
 if err:=Validate(s,policy);err!=nil{t.Fatal(err)}
 first:=bunnyscript.EvidenceSummary{Outcome:"repeated_candidate_with_negative_controls"}
 next,stop,reason:=NextIndex(s,1,first,false)
 if next!=1||stop||reason!="repeat_same_candidate_with_fresh_capture"{t.Fatal("candidate not repeated")}
 _,stop,reason=NextIndex(s,1,first,true)
 if !stop||!strings.Contains(reason,"unverified")&&!strings.Contains(reason,"independent"){t.Fatal("replication overclaimed confirmed exploit")}
 inconclusive:=bunnyscript.EvidenceSummary{Outcome:"inconclusive_or_failed_control"}
 next,stop,_=NextIndex(s,0,inconclusive,false)
 if stop||next!=1{t.Fatal("inconclusive outcome did not advance to next approved target")}
}
