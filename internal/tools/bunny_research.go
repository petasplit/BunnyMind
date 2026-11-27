package tools

import (
 "context"
 "encoding/json"

 "github.com/enowdev/antares/internal/bunnyresearch"
)

// researchNextStepTool is a bounded, offline feedback classifier that helps
// agents avoid treating blocked or failed tests as vulnerability disproof.
type researchNextStepTool struct{}
func (researchNextStepTool) Name()string{return "research_next_step"}
func (researchNextStepTool) Description()string{
 return "Reason about structured, caller-supplied test observations: baseline, "+
 "negative control, candidate signal, intermediary block, transport error, "+
 "repetition and evidence budget. Recommend a safe next experiment type, "+
 "not an exploit payload or WAF bypass. The canary option creates only "+
 "a random harmless marker. This tool does not send requests or verify "+
 "that submitted evidence digests are authentic."
}
func (researchNextStepTool) RequiresApproval()bool{return false}
func (researchNextStepTool) Schema()map[string]any{
 return schema(map[string]any{
  "action":propEnum("Tool operation.","analyze","mint_benign_canary"),
  "case_id":prop("string","Stable case ID for analyze."),
  "kind":propEnum("Hypothesis category.","authorization","input_handling","server_execution","business_logic"),
  "budget":prop("integer","Maximum 1..64 observations allocated for this case."),
  "observations":map[string]any{
   "type":"array",
   "description":"Structured observations, not raw requests or secret material.",
   "items":map[string]any{
    "type":"object","properties":map[string]any{
     "id":prop("string","Unique observation ID."),
     "role":propEnum("Control role.","baseline","control","candidate"),
     "signal":propEnum("Observed classification.","normal","denied","marker","intermediary_block","transport_error","server_error"),
     "treatment_sha256":prop("string","SHA-256 fingerprint of treatment identity, not raw payload."),
     "evidence_sha256":prop("string","SHA-256 fingerprint of sanitized observation; not independently verified."),
    },
    "required":[]string{"id","role","signal","treatment_sha256","evidence_sha256"},
   },
  },
 },"action")
}
func (researchNextStepTool) Execute(_ context.Context,in Input)Result{
 var args struct{
  Action string `json:"action"`
  CaseID string `json:"case_id"`
  Kind string `json:"kind"`
  Budget int `json:"budget"`
  Observations []bunnyresearch.Observation `json:"observations"`
 }
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid research state: %v",err)}
 if args.Action=="mint_benign_canary"{
  s,err:=bunnyresearch.Canary();if err!=nil{return Errorf("could not create benign canary: %v",err)}
  return Text(s)
 }
 if args.Action!="analyze"{return Errorf("unsupported research action")}
 report,err:=bunnyresearch.Analyze(bunnyresearch.Study{
  CaseID:args.CaseID,Kind:args.Kind,Budget:args.Budget,Observations:args.Observations,
 })
 if err!=nil{return Errorf("research state invalid: %v",err)}
 b,err:=json.MarshalIndent(report,"","  ");if err!=nil{return Errorf("could not serialize next experiment: %v",err)}
 return Text(string(b))
}
