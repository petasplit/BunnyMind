package server

import (
 "encoding/json"
 "os"
 "path/filepath"
 "testing"

 "github.com/enowdev/antares/internal/bunnyscript"
)
func writeProofCatalogFixture(t *testing.T,folder string,plan bunnyscript.Plan,kind string){
 t.Helper()
 if err:=os.MkdirAll(folder,0700);err!=nil{t.Fatal(err)}
 b,_:=json.Marshal(plan)
 if err:=os.WriteFile(filepath.Join(folder,"plan.json"),b,0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(folder,"scenario.py"),[]byte("print('fixture-only')"),0600);err!=nil{t.Fatal(err)}
 if kind=="draft"{
  if err:=os.WriteFile(filepath.Join(folder,"idea.json"),[]byte(`{"theme":"marker_provenance","candidate_index":0,"control_index":0}`),0600);err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(filepath.Join(folder,"oracle.py"),[]byte("print('offline')"),0600);err!=nil{t.Fatal(err)}
 }else{
  summary:=bunnyscript.EvidenceSummary{EngagementID:plan.EngagementID,RunID:plan.RunID,
   Outcome:"inconclusive_or_failed_control",ScriptSHA256:"filehash",ScriptFile:"scenario.py",
   Cases:4,RawEvidenceFile:"transcript.enc"}
  data,_:=json.Marshal(summary)
  if err:=os.WriteFile(filepath.Join(folder,"validation.json"),data,0600);err!=nil{t.Fatal(err)}
 }
}
func TestPythonProofCatalogListsNestedCampaignAndDraftsWithoutCrossEngagement(t *testing.T){
 root:=t.TempDir()
 mk:=func(eng,run,folder,kind string){
  writeProofCatalogFixture(t,folder,bunnyscript.Plan{EngagementID:eng,RunID:run},kind)
 }
 mk("eng-A","single",filepath.Join(root,"single"),"run")
 mk("eng-A","camp-r01",filepath.Join(root,"camp","camp-r01"),"run")
 mk("eng-A","draft-run",filepath.Join(root,"camp","drafts","idea_1234"),"draft")
 mk("eng-B","foreign",filepath.Join(root,"foreign"),"run")
 rows,err:=listedProofRuns(root,"eng-A")
 if err!=nil{t.Fatal(err)}
 if len(rows)!=3{t.Fatalf("expected 3 authorized records, got %+v",rows)}
 found:=map[string]bool{}
 for _,row:=range rows{
  found[row.RunID]=true
  if row.RunID=="foreign"{t.Fatal("cross-engagement evidence catalog disclosure")}
  if row.RunID=="idea_1234"{
   if row.Kind!="draft"||row.CampaignID!="camp"||row.RawEncrypted{
    t.Fatalf("unexecuted model hypothesis mislabeled as captured: %+v",row)
   }
  }
 }
 for _,v:=range []string{"single","camp-r01","idea_1234"}{if !found[v]{t.Fatalf("missing %s",v)}}
}
