package server

import (
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "os"
 "path/filepath"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyscript"
)
type proofRunView struct{
 RunID string `json:"run_id"`
 CampaignID string `json:"campaign_id,omitempty"`
 Kind string `json:"kind,omitempty"`
 Outcome string `json:"outcome"`
 ScriptSHA256 string `json:"script_sha256"`
 ScriptName string `json:"script_name"`
 Cases int `json:"cases"`
 RawEncrypted bool `json:"raw_encrypted"`
}
func readSmall(path string,max int)([]byte,error){
 fd,err:=os.Open(path);if err!=nil{return nil,err}
 defer fd.Close()
 b,err:=io.ReadAll(io.LimitReader(fd,int64(max+1)))
 if err!=nil||len(b)>max{return nil,errors.New("evidence file too large")}
 return b,nil
}
func listedProofRuns(root,engagement string)([]proofRunView,error){
 dirs,err:=os.ReadDir(root)
 if os.IsNotExist(err){return []proofRunView{},nil}
 if err!=nil{return nil,err}
 out:=[]proofRunView{}
 appendRun:=func(folder,runID,campaign,kind string){
  if !bunnyscript.ValidRunID(runID){return}
  raw,e:=readSmall(filepath.Join(folder,"plan.json"),32*1024)
  if e!=nil{return}
  var plan bunnyscript.Plan
  if json.Unmarshal(raw,&plan)!=nil||plan.EngagementID!=engagement{
   return
  }
  if kind!="draft"&&plan.RunID!=runID{return}
  if kind=="draft"{
   idea,e:=readSmall(filepath.Join(folder,"idea.json"),4096)
   if e!=nil||len(idea)==0{return}
   script,e:=readSmall(filepath.Join(folder,"scenario.py"),128*1024)
   if e!=nil{return}
   out=append(out,proofRunView{CampaignID:campaign,RunID:runID,Kind:"draft",
    Outcome:"draft_not_executed",ScriptName:"scenario.py",ScriptSHA256:bunnyscript.SHA(script),
    Cases:len(plan.Cases),RawEncrypted:false})
   return
  }
  raw,e=readSmall(filepath.Join(folder,"validation.json"),64*1024)
  if e!=nil{return}
  var summary bunnyscript.EvidenceSummary
  if json.Unmarshal(raw,&summary)!=nil||summary.EngagementID!=engagement||
   summary.RunID!=runID{return}
  out=append(out,proofRunView{CampaignID:campaign,RunID:runID,Kind:"run",
   Outcome:summary.Outcome,ScriptName:summary.ScriptFile,
   ScriptSHA256:summary.ScriptSHA256,Cases:summary.Cases,
   RawEncrypted:summary.RawEvidenceFile!=""})
 }
 for _,entry:=range dirs{
  if !entry.IsDir()||!bunnyscript.ValidRunID(entry.Name()){continue}
  folder:=filepath.Join(root,entry.Name())
  appendRun(folder,entry.Name(),"","run")
  if len(out)>=100{break}
  children,e:=os.ReadDir(folder)
  if e!=nil{continue}
  for _,child:=range children{
   if !child.IsDir(){continue}
   if child.Name()=="drafts"{
    drafts,e:=os.ReadDir(filepath.Join(folder,"drafts"))
    if e!=nil{continue}
    for _,draft:=range drafts{
     if draft.IsDir(){
      appendRun(filepath.Join(folder,"drafts",draft.Name()),draft.Name(),entry.Name(),"draft")
     }
     if len(out)>=100{break}
    }
   }else{
    appendRun(filepath.Join(folder,child.Name()),child.Name(),entry.Name(),"run")
   }
   if len(out)>=100{break}
  }
  if len(out)>=100{break}
 }
 return out,nil
}
// GET /api/engagement/python-proofs lists only sanitized evidence metadata.
// With run and artifact=script|validation it reveals exactly the generated
// source or sanitized proof summary. AES-GCM raw captures are never served.
func (s *Server) handlePythonProofs(w http.ResponseWriter,r *http.Request){
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 root:=strings.TrimSpace(os.Getenv("BUNNY_PROOF_OUTPUT"))
 if policyPath==""||root==""{
  writeError(w,http.StatusNotFound,errors.New("Python proof vault not configured"));return
 }
 guard,err:=bunnyguard.New(policyPath)
 if err!=nil{writeError(w,http.StatusServiceUnavailable,errors.New("invalid engagement manifest"));return}
 runs,err:=listedProofRuns(root,guard.Manifest().EngagementID)
 if err!=nil{writeError(w,http.StatusInternalServerError,errors.New("proof vault unavailable"));return}
 runID:=r.URL.Query().Get("run")
 if runID==""{
  writeJSON(w,http.StatusOK,map[string]any{"runs":runs,
   "note":"Raw request/response proofs and screenshots are encrypted. Export explicitly with the local CLI for authorized triage."})
  return
 }
 if !bunnyscript.ValidRunID(runID){writeError(w,http.StatusBadRequest,errors.New("invalid proof run"));return}
 campaignID:=r.URL.Query().Get("campaign")
 if campaignID!=""&&!bunnyscript.ValidRunID(campaignID){
  writeError(w,http.StatusBadRequest,errors.New("invalid campaign identifier"));return
 }
 var selected *proofRunView
 for i:=range runs{
  if runs[i].RunID==runID&&runs[i].CampaignID==campaignID{
   selected=&runs[i];break
  }
 }
 if selected==nil{
  writeError(w,http.StatusNotFound,errors.New("proof run not found for this engagement"));return
 }
 name,max:="",0
 switch r.URL.Query().Get("artifact"){
 case "script":name="scenario.py";max=128*1024
 case "validation":
  if selected.Kind=="draft"{name="idea.json";max=4096
  }else{name="validation.json";max=64*1024}
 case "oracle":
  if selected.Kind!="draft"{writeError(w,http.StatusBadRequest,errors.New("oracle is available only for hypothesis drafts"));return}
  name="oracle.py";max=128*1024
 default:writeError(w,http.StatusBadRequest,errors.New("only generated source and sanitized validation are viewable"));return
 }
 folder:=filepath.Join(root,runID)
 if campaignID!=""{
  if selected.Kind=="draft"{folder=filepath.Join(root,campaignID,"drafts",runID)
  }else{folder=filepath.Join(root,campaignID,runID)}
 }
 b,err:=readSmall(filepath.Join(folder,name),max)
 if err!=nil{writeError(w,http.StatusNotFound,errors.New("proof artifact unavailable"));return}
 w.Header().Set("Cache-Control","no-store")
 writeJSON(w,http.StatusOK,map[string]any{"run_id":runID,"artifact":name,"contents":string(b)})
}
