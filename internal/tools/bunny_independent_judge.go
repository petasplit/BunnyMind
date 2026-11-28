package tools

import (
 "context"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnyjudge"
)
type independentEvidenceJudgeTool struct{}
func (independentEvidenceJudgeTool) Name()string{return "independent_evidence_judge"}
func (independentEvidenceJudgeTool) Description()string{
 return "Independently review exactly one operator-selected sealed Python proof run. "+
  "Recompute all captured request/response and negative-control observations "+
  "from locally encrypted evidence, authenticate the seal and report whether "+
  "the signal replicated. Does not assert exploitability or make network "+
  "requests. Requires BUNNY_EVIDENCE_JUDGE_RUN set by operator."
}
func (independentEvidenceJudgeTool) RequiresApproval()bool{return false}
func (independentEvidenceJudgeTool) Schema()map[string]any{return schema(map[string]any{})}
func (independentEvidenceJudgeTool) Execute(_ context.Context,in Input)Result{
 if len(in.Args)>0&&strings.TrimSpace(string(in.Args))!="{}"{return Errorf("judge accepts no model-written evidence path")}
 folder:=strings.TrimSpace(os.Getenv("BUNNY_EVIDENCE_JUDGE_RUN"))
 if folder==""{return Errorf("operator must select a sealed evidence run for independent review")}
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return Errorf("private evidence key unavailable")}
 verdict,err:=bunnyjudge.JudgeRun(folder,key)
 if err!=nil{return Errorf("independent reviewer rejected run: %v",err)}
 raw,err:=json.MarshalIndent(verdict,"","  ")
 if err!=nil{return Errorf("judge verdict serialization failed")}
 return Text(string(raw))
}
