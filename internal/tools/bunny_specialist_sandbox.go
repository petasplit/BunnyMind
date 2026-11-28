package tools

import (
 "context"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnysandbox"
)

type sandboxSpecialistTool struct{}
func (sandboxSpecialistTool) Name()string{return "sandbox_specialist"}
func (sandboxSpecialistTool) Description()string{
 return "Execute one operator-reviewed, pinned-image offline specialist profile "+
  "inside Docker with network disabled, read-only host input, no privileges, "+
  "strict CPU/memory/PID/time limits and encrypted output. The model cannot "+
  "specify a command, image, script, network target, credential or filesystem path. "+
  "Requires trusted BUNNY_SPECIALIST_SANDBOX_PROFILE and BUNNY_PROOF_OUTPUT."
}
func (sandboxSpecialistTool) RequiresApproval()bool{return false}
func (sandboxSpecialistTool) Schema()map[string]any{return schema(map[string]any{})}
func (sandboxSpecialistTool) Execute(ctx context.Context,in Input)Result{
 if len(in.Args)>0&&strings.TrimSpace(string(in.Args))!="{}"{return Errorf("sandbox accepts no model command arguments")}
 file:=strings.TrimSpace(os.Getenv("BUNNY_SPECIALIST_SANDBOX_PROFILE"))
 output:=strings.TrimSpace(os.Getenv("BUNNY_PROOF_OUTPUT"))
 if file==""||output==""{return Errorf("operator-provisioned sandbox profile and vault are required")}
 p,err:=bunnysandbox.LoadSpec(file)
 if err!=nil{return Errorf("invalid trusted sandbox profile: %v",err)}
 if in.Emit!=nil{in.Emit(Progress{Tool:"sandbox_specialist",Message:"Running approved offline specialist in isolated Docker container"})}
 report,err:=bunnysandbox.Run(ctx,p,output)
 if err!=nil{return Errorf("specialist isolation unavailable: %v",err)}
 raw,err:=json.MarshalIndent(report,"","  ")
 if err!=nil{return Errorf("cannot encode sandbox receipt")}
 return Text(string(raw))
}
