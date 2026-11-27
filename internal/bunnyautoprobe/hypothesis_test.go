package bunnyautoprobe

import (
 "encoding/json"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyscript"
)
func TestAIHypothesisCompilesInspectablePythonAndIndependentOracle(t *testing.T){
 s,policy,closeFixture:=controlled(t);defer closeFixture()
 idea:=Idea{Theme:"authorization_boundary",CandidateIndex:1,ControlIndex:0}
 root:=t.TempDir()
 output,err:=Draft(root,s,idea,policy)
 if err!=nil{t.Fatal(err)}
 if output.Status!="draft_not_executed"||output.ScriptSHA256==""||output.OracleSHA256==""{
  t.Fatalf("draft claimed work or lost source hashes %+v",output)
 }
 folder:=filepath.Join(root,s.CampaignID,"drafts",output.HypothesisID)
 script,err:=os.ReadFile(filepath.Join(folder,"scenario.py"))
 if err!=nil||bunnyscript.SHA(script)!=output.ScriptSHA256||!strings.Contains(string(script),"/candidate-good"){
  t.Fatalf("AI-selected plan not compiled into exact Python source: %v",err)
 }
 oracle,err:=os.ReadFile(filepath.Join(folder,"oracle.py"))
 if err!=nil||bunnyscript.SHA(oracle)!=output.OracleSHA256{
  t.Fatalf("offline oracle not preserved: %v",err)
 }
 python,err:=exec.LookPath("python3")
 if err!=nil{python,err=exec.LookPath("python")}
 if err!=nil{t.Skip("Python unavailable")}
 validation:=bunnyscript.EvidenceSummary{Receipts:[]bunnyscript.SampleReceipt{
  {SampleID:"candidate_first",Kind:"candidate",Status:200,MarkerPresent:true},
  {SampleID:"control_first",Kind:"control",Status:403},
  {SampleID:"candidate_repeat",Kind:"candidate",Status:200,MarkerPresent:true},
  {SampleID:"control_repeat",Kind:"control",Status:403},
 }}
 data,_:=json.Marshal(validation)
 validationPath:=filepath.Join(folder,"synthetic-validation.json")
 if err:=os.WriteFile(validationPath,data,0600);err!=nil{t.Fatal(err)}
 result,err:=exec.Command(python,"-I","-S",filepath.Join(folder,"oracle.py"),validationPath).Output()
 if err!=nil||!strings.Contains(string(result),`"signal_observed": true`)||
 !strings.Contains(string(result),"unverified_observation"){
  t.Fatalf("offline proof oracle did not recognize status controls: %s %v",result,err)
 }
 validation.Receipts[0].MarkerInRequest=true
 data,_=json.Marshal(validation)
 if err:=os.WriteFile(validationPath,data,0600);err!=nil{t.Fatal(err)}
 result,err=exec.Command(python,"-I","-S",filepath.Join(folder,"oracle.py"),validationPath).Output()
 if err!=nil||!strings.Contains(string(result),`"signal_observed": false`){
  t.Fatalf("reflected request marker incorrectly accepted: %s %v",result,err)
 }
}
func TestModelCannotDraftOutsideOperatorInventory(t *testing.T){
 s,policy,closeFixture:=controlled(t);defer closeFixture()
 ideas:=[]Idea{
  {Theme:"command_exec",CandidateIndex:0,ControlIndex:0},
  {Theme:"authorization_boundary",CandidateIndex:99,ControlIndex:0},
  {Theme:"marker_provenance",CandidateIndex:0,ControlIndex:99},
  {Theme:"status_differential",CandidateIndex:-1,ControlIndex:0},
 }
 for _,idea:=range ideas{
  if _,err:=Draft(t.TempDir(),s,idea,policy);err==nil{
   t.Fatalf("unapproved model idea compiled: %+v",idea)
  }
 }
 idea:=Idea{Theme:"marker_provenance",CandidateIndex:0,ControlIndex:0}
 root:=t.TempDir()
 if _,err:=Draft(root,s,idea,policy);err!=nil{t.Fatal(err)}
 if _,err:=Draft(root,s,idea,policy);err==nil{t.Fatal("replaced immutable previous Python draft")}
}
