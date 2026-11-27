package bunnyautoprobe

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyscript"
)
var hypothesisThemes=map[string]bool{
 "authorization_boundary":true,
 "session_boundary":true,
 "input_consistency":true,
 "status_differential":true,
 "marker_provenance":true,
}
// Idea is the only model-proposed input to the Python compiler. The model
// selects indices from a separate operator-approved endpoint inventory; it
// cannot supply a URL, Python source, payload or privileged action.
type Idea struct{
 Theme string `json:"theme"`
 CandidateIndex int `json:"candidate_index"`
 ControlIndex int `json:"control_index"`
}
type DraftSummary struct{
 CampaignID string `json:"campaign_id"`
 HypothesisID string `json:"hypothesis_id"`
 Theme string `json:"theme"`
 ScriptFile string `json:"script_file"`
 ScriptSHA256 string `json:"script_sha256"`
 OracleFile string `json:"oracle_file"`
 OracleSHA256 string `json:"oracle_sha256"`
 CandidatePathSHA256 string `json:"candidate_path_sha256"`
 ControlPathSHA256 string `json:"control_path_sha256"`
 Status string `json:"status"`
 Limitations string `json:"limitations"`
}
func ValidateIdea(s Spec,idea Idea,policy bunnyguard.Policy)error{
 if err:=Validate(s,policy);err!=nil{return err}
 if !hypothesisThemes[idea.Theme]{
  return errors.New("idea must select an approved non-destructive evidence hypothesis")
 }
 if idea.CandidateIndex<0||idea.CandidateIndex>=len(s.CandidatePaths)||
 idea.ControlIndex<0||idea.ControlIndex>=len(s.NegativeControlPaths){
  return errors.New("idea references an endpoint outside approved inventory")
 }
 return nil
}
func ideaPlan(s Spec,idea Idea,runID string)bunnyscript.Plan{
 p:=PlanFor(s,0,idea.CandidateIndex)
 p.RunID=runID
 path:=s.NegativeControlPaths[idea.ControlIndex]
 p.Cases[1].Path=path
 p.Cases[3].Path=path
 return p
}
func oracleSource(theme string)[]byte{
 // The exact oracle program is included beside its generated HTTP script.
 // This code executes offline only and reads the saved sanitized validation.
 code:=`#!/usr/bin/env python3
"""BunnyMind independent offline oracle for an approved proof scenario."""
import json
import sys

THEME = __THEME__
def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: oracle.py validation.json")
    with open(sys.argv[1], "r", encoding="utf-8") as fd:
        study = json.load(fd)
    receipts = study.get("receipts", [])
    candidates = [r for r in receipts if r.get("kind") == "candidate"]
    controls = [r for r in receipts if r.get("kind") == "control"]
    reliable = (len(candidates) >= 2 and len(controls) >= 2
        and not any(r.get("truncated") for r in receipts)
        and not any(r.get("marker_in_request") for r in candidates))
    if THEME in ("authorization_boundary", "session_boundary", "status_differential"):
        candidate_ok = all(200 <= int(r.get("status", 0)) < 400 for r in candidates)
        control_ok = all(400 <= int(r.get("status", 0)) < 500 for r in controls)
        signal = reliable and candidate_ok and control_ok
    elif THEME == "input_consistency":
        statuses = [r.get("status") for r in candidates]
        signal = reliable and len(set(statuses)) == 1 and bool(statuses) and statuses[0] < 500
    else:
        signal = reliable and all(r.get("marker_present") for r in candidates) and not any(
            r.get("marker_present") for r in controls)
    print(json.dumps({"theme": THEME, "signal_observed": signal,
       "assessment": "unverified_observation" if signal else "inconclusive",
       "warning": "A status difference or marker is not independent proof of exploit impact."},
       sort_keys=True))
if __name__ == "__main__":
    main()
`
 return []byte(strings.ReplaceAll(code,"__THEME__",fmt.Sprintf("%q",theme)))
}
func Draft(root string,s Spec,idea Idea,policy bunnyguard.Policy)(DraftSummary,error){
 if err:=ValidateIdea(s,idea,policy);err!=nil{return DraftSummary{},err}
 if root==""||len(root)>2048{return DraftSummary{},errors.New("trusted draft destination required")}
 seed:=fmt.Sprintf("%s|%s|%d|%d",s.CampaignID,idea.Theme,idea.CandidateIndex,idea.ControlIndex)
 h:=sha256.Sum256([]byte(seed))
 id:="idea_"+hex.EncodeToString(h[:8])
 runID:=s.CampaignID+"_h"+hex.EncodeToString(h[:4])
 p:=ideaPlan(s,idea,runID)
 if err:=bunnyscript.Validate(p,policy);err!=nil{return DraftSummary{},err}
 script,err:=bunnyscript.Generate(p)
 if err!=nil{return DraftSummary{},err}
 oracle:=oracleSource(idea.Theme)
 parent:=filepath.Join(root,s.CampaignID,"drafts")
 if err:=os.MkdirAll(parent,0700);err!=nil{return DraftSummary{},err}
 folder:=filepath.Join(parent,id)
 if err:=os.Mkdir(folder,0700);err!=nil{
  return DraftSummary{},errors.New("hypothesis draft already exists or cannot be created")
 }
 files:=map[string][]byte{
  "scenario.py":script,"oracle.py":oracle,
 }
 for name,bytes:=range files{
  if err:=os.WriteFile(filepath.Join(folder,name),bytes,0600);err!=nil{return DraftSummary{},err}
 }
 planBytes,_:=json.MarshalIndent(p,"","  ")
 if err:=os.WriteFile(filepath.Join(folder,"plan.json"),planBytes,0600);err!=nil{return DraftSummary{},err}
 ideaBytes,_:=json.MarshalIndent(idea,"","  ")
 if err:=os.WriteFile(filepath.Join(folder,"idea.json"),ideaBytes,0600);err!=nil{return DraftSummary{},err}
 result:=DraftSummary{
  CampaignID:s.CampaignID,HypothesisID:id,Theme:idea.Theme,
  ScriptFile:filepath.Join(s.CampaignID,"drafts",id,"scenario.py"),
  ScriptSHA256:bunnyscript.SHA(script),
  OracleFile:filepath.Join(s.CampaignID,"drafts",id,"oracle.py"),
  OracleSHA256:bunnyscript.SHA(oracle),
  CandidatePathSHA256:bunnyscript.SHA([]byte(p.Cases[0].Path)),
  ControlPathSHA256:bunnyscript.SHA([]byte(p.Cases[1].Path)),
  Status:"draft_not_executed",
  Limitations:"Model-selected hypothesis from an operator-owned inventory. Python is synthesized from reviewed code, not copied from the model. No network action was performed or vulnerability confirmed.",
 }
 return result,nil
}
