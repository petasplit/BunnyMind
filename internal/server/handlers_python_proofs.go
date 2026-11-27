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
 for _,entry:=range dirs{
  if !entry.IsDir()||!bunnyscript.ValidRunID(entry.Name()){continue}
  folder:=filepath.Join(root,entry.Name())
  b,e:=readSmall(filepath.Join(folder,"plan.json"),32*1024)
  if e!=nil{continue}
  var plan bunnyscript.Plan
  if json.Unmarshal(b,&plan)!=nil||plan.EngagementID!=engagement||plan.RunID!=entry.Name(){continue}
  b,e=readSmall(filepath.Join(folder,"validation.json"),64*1024)
  if e!=nil{continue}
  var summary bunnyscript.EvidenceSummary
  if json.Unmarshal(b,&summary)!=nil||summary.EngagementID!=engagement||summary.RunID!=entry.Name(){continue}
  out=append(out,proofRunView{RunID:entry.Name(),Outcome:summary.Outcome,
   ScriptSHA256:summary.ScriptSHA256,ScriptName:summary.ScriptFile,
   Cases:summary.Cases,RawEncrypted:summary.RawEvidenceFile!=""})
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
 present:=false
 for _,run:=range runs{if run.RunID==runID{present=true;break}}
 if !present{writeError(w,http.StatusNotFound,errors.New("proof run not found for this engagement"));return}
 name,max:="",0
 switch r.URL.Query().Get("artifact"){
 case "script":name="scenario.py";max=128*1024
 case "validation":name="validation.json";max=64*1024
 default:writeError(w,http.StatusBadRequest,errors.New("only generated source and sanitized validation are viewable"));return
 }
 b,err:=readSmall(filepath.Join(root,runID,name),max)
 if err!=nil{writeError(w,http.StatusNotFound,errors.New("proof artifact unavailable"));return}
 w.Header().Set("Cache-Control","no-store")
 writeJSON(w,http.StatusOK,map[string]any{"run_id":runID,"artifact":name,"contents":string(b)})
}
