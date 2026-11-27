package tools

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnyautoprobe"
 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyscript"
 "github.com/enowdev/antares/internal/bunnytimeline"
)
const adaptiveProofSpecEnv="BUNNY_ADAPTIVE_PROOF_SPEC"
type adaptivePythonProofTool struct{}
func (adaptivePythonProofTool) Name()string{return "python_adaptive_proof_run"}
func (adaptivePythonProofTool) Description()string{
 return "Independently synthesize and execute a sequence of reproducible Python evidence scripts "+
 "from the local operator's approved endpoint inventory. Each round includes two candidate "+
 "requests and two negative controls. A promising signal is independently rerun once; "+
 "inconclusive evidence changes to another preapproved candidate, subject to shared "+
 "study time/request budgets. Preserve source code, exact encrypted HTTP transcripts, "+
 "independent hash validation, and a reproducible campaign report. "+
 "No arbitrary Python source, exploit payload, target URL, credentials or scope expansion "+
 "is accepted from the model. No marker-only result is a verified vulnerability."
}
func (adaptivePythonProofTool) RequiresApproval()bool{return false}
func (adaptivePythonProofTool) Schema()map[string]any{return schema(map[string]any{})}
func (adaptivePythonProofTool) Execute(ctx context.Context,in Input)Result{
 if len(in.Args)>0&&string(in.Args)!="{}"{
  return Errorf("adaptive proof runner takes no model-provided arguments")
 }
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 specPath:=strings.TrimSpace(os.Getenv(adaptiveProofSpecEnv))
 root:=strings.TrimSpace(os.Getenv(proofRootEnv))
 if policyPath==""||specPath==""||root==""{
  return Errorf("operator-managed BunnyGuard, adaptive specification and evidence root required")
 }
 guard,err:=bunnyguard.New(policyPath)
 if err!=nil{return Errorf("invalid BunnyGuard policy")}
 raw,err:=os.ReadFile(specPath)
 if err!=nil{return Errorf("approved adaptive testing inventory not available")}
 spec,err:=bunnyautoprobe.Load(raw,guard.Manifest())
 if err!=nil{return Errorf("adaptive testing scope denied: %v",err)}
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return Errorf("private evidence key unavailable")}
 summary,err:=(bunnyautoprobe.Runner{
  Proof:bunnyscript.Runner{
   Python:os.Getenv("BUNNY_PYTHON"),Root:root,EncryptionKey:key,
   Secrets:bunnybrowserflow.KeyringSecrets{},
  },
 }).Execute(ctx,spec,guard.Manifest())
 if err!=nil{
  return Errorf("adaptive proof capture incomplete: %v",err)
 }
 payload,err:=json.MarshalIndent(summary,"","  ")
 if err!=nil{return Errorf("could not encode adaptive evidence summary")}
 result:=Text(string(payload))
 if in.SessionID!="" {
  h:=sha256.Sum256(payload)
  _,err=timelineStore().Append(in.SessionID,bunnytimeline.Entry{
   Lane:"evidence",Action:"verify",State:"succeeded",Source:bunnytimeline.SourceTool,
   AssetID:"adaptive_"+hex.EncodeToString(h[:8]),EvidenceSHA256:hex.EncodeToString(h[:]),
  })
  if err!=nil{result.Meta=map[string]any{"timeline_warning":"capture saved but timeline update failed"}}
 }
 return result
}
