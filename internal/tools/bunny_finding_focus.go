package tools

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "regexp"
 "strings"

 "github.com/enowdev/antares/internal/findings"
)

// findingFocusTool supports DorkixAI-style per-finding investigation without
// exposing secrets or treating a model assertion as corroborating evidence.
type findingFocusTool struct{}
var findingRef=regexp.MustCompile(`^F-[0-9]{3,6}$`)
func (findingFocusTool) Name() string {return "finding_focus"}
func (findingFocusTool) Description()string{
 return "Interact with a specific recorded finding: inspect its evidence state, "+
 "ask a bounded question about proof gaps, obtain an independent retest "+
 "checklist or remediation review. Uses only the current engagement ledger. "+
 "No raw PoC, passwords, tokens, request bodies or target URLs are returned; "+
 "does not execute exploits or mark a finding verified."
}
func (findingFocusTool) Schema()map[string]any{
 return schema(map[string]any{
  "finding_id":prop("string","Existing finding in the current engagement, e.g. F-001."),
  "action":propEnum("Finding interaction.","inspect","ask","retest","remediation"),
  "question":prop("string","For ask only: short question on impact, evidence, or next steps; never include credentials."),
 },"finding_id","action")
}
func (findingFocusTool) RequiresApproval()bool{return false}
func (findingFocusTool) Execute(_ context.Context,in Input)Result{
 if in.Deps==nil||in.Deps.Findings==nil||in.SessionID==""{return Errorf("finding ledger and session required")}
 if len(in.Args)>4096{return Errorf("finding focus arguments exceed limit")}
 var args struct{
  ID string `json:"finding_id"`
  Action string `json:"action"`
  Question string `json:"question"`
 }
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid finding focus input")}
 if !findingRef.MatchString(args.ID)||len(args.Question)>240{return Errorf("invalid finding id or question length")}
 list,err:=in.Deps.Findings.List(in.SessionID)
 if err!=nil{return Errorf("cannot read engagement findings")}
 var selected *findings.Finding
 for i:=range list{
  if list[i].ID==args.ID{selected=&list[i];break}
 }
 if selected==nil{return Errorf("finding is not present in this engagement")}
 f:=*selected
 gaps:=[]string{}
 if f.Reproduce==""{gaps=append(gaps,"missing reproduction steps")}
 if f.PoC==""{gaps=append(gaps,"missing captured proof of concept")}
 if f.Impact==""{gaps=append(gaps,"missing documented security impact")}
 if f.Remediation==""{gaps=append(gaps,"missing remediation")}
 if f.Target==""{gaps=append(gaps,"missing affected asset")}
 digest:=sha256.Sum256([]byte(f.ID+"|"+f.Reproduce+"|"+f.PoC))
 report:=map[string]any{
  "finding_id":f.ID,"recorded_severity":f.Severity,"triage_status":f.Status,
  "classification":f.CWE,"evidence_reference_sha256":hex.EncodeToString(digest[:]),
  "has_reproduction":f.Reproduce!="","has_poc":f.PoC!="",
  "has_impact":f.Impact!="","has_remediation":f.Remediation!="",
  "evidence_gaps":gaps,
  "note":"Evidence hashes are derived from stored text and are not independent proof that a vulnerability was reproduced.",
 }
 switch args.Action {
 case "inspect":
  report["next"]="Use independent test-account controls before confirming recorded severity."
 case "ask":
  q:=strings.ToLower(args.Question)
  switch{
  case strings.Contains(q,"fix")||strings.Contains(q,"mitigat")||strings.Contains(q,"remediat"):
   report["answer"]="Review the stored remediation with the application owner and verify the fix using a scope-approved regression test. Raw remediation text is intentionally withheld."
  case strings.Contains(q,"impact")||strings.Contains(q,"severity"):
   report["answer"]="The recorded impact and severity are claims until independently corroborated; prioritize isolated test resources and negative controls."
  default:
   report["answer"]="Check whether the ledger includes independent proof, steps and controls; use the retest action to produce a reproducible verification checklist."
  }
 case "retest":
  report["review_steps"]=[]string{
   "Freeze the exact authorized test scope and test-account identities.",
   "Capture a sanitized owner baseline and a distinct negative control.",
   "Reproduce the observable behavior at a bounded request rate with harmless test data.",
   "Correlate separate evidence digests and observed impact before triage.",
  }
 case "remediation":
  report["review_steps"]=[]string{
   "Compare the documented fix against the confirmed root cause.",
   "Use approved regression fixtures to check both positive and negative controls.",
   "Do not mark fixed until independent retest evidence is recorded.",
  }
 default:return Errorf("unsupported finding focus action")
 }
 b,err:=json.MarshalIndent(report,"","  ")
 if err!=nil{return Errorf("cannot encode finding focus result")}
 return Text(string(b))
}
