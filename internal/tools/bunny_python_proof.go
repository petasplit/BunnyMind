package tools

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyscript"
 "github.com/enowdev/antares/internal/bunnytimeline"
)
const (
 proofPlanEnv="BUNNY_PROOF_PLAN"
 proofRootEnv="BUNNY_PROOF_OUTPUT"
)
type pythonProofRunTool struct{}
func (pythonProofRunTool) Name()string{return "python_proof_run"}
func (pythonProofRunTool) Description()string{
 return "Generate, save and execute a reviewed Python test script for a "+
 "preapproved HTTP evidence plan, with repeated candidate and negative-control "+
 "requests. Uses only operator-configured BunnyGuard, test-account cookies from "+
 "the OS keyring, and DNS-pinned HTTPS egress. Saves scenario.py and plan.json, "+
 "stores complete captured HTTP transcripts in an AES-GCM evidence vault, "+
 "then reports source hashes, case statuses and validation gaps. "+
 "No arbitrary target, Python code, payload, cookie or secret is accepted from the model; "+
 "does not claim a vulnerability is verified by a reflected marker."
}
func (pythonProofRunTool) Schema()map[string]any{return schema(map[string]any{})}
func (pythonProofRunTool) RequiresApproval()bool{return false}
func (pythonProofRunTool) Execute(ctx context.Context,in Input)Result{
 if len(in.Args)>0&&string(in.Args)!="{}"{return Errorf("Python proof runner accepts no model-supplied code, target or test-plan arguments")}
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 planPath:=strings.TrimSpace(os.Getenv(proofPlanEnv))
 root:=strings.TrimSpace(os.Getenv(proofRootEnv))
 if policyPath==""||planPath==""||root==""{
  return Errorf("operator-configured BunnyGuard, proof plan and local output directory are required")
 }
 guard,err:=bunnyguard.New(policyPath)
 if err!=nil{return Errorf("invalid engagement authorization")}
 file,err:=os.ReadFile(planPath)
 if err!=nil{return Errorf("approved scenario file is unavailable")}
 p,err:=bunnyscript.ValidateJSON(file,guard.Manifest())
 if err!=nil{return Errorf("Python proof scenario not authorized: %v",err)}
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return Errorf("evidence vault key unavailable: %v",err)}
 summary,err:=(bunnyscript.Runner{
  Root:root,Python:os.Getenv("BUNNY_PYTHON"),EncryptionKey:key,
  Secrets:bunnybrowserflow.KeyringSecrets{},
 }).Run(ctx,p,guard.Manifest())
 if err!=nil{return Errorf("approved Python evidence run did not complete: %v",err)}
 output,err:=json.MarshalIndent(summary,"","  ")
 if err!=nil{return Errorf("evidence summary unavailable")}
 result:=Text(string(output))
 if in.SessionID!=""{
  digest:=sha256.Sum256(output)
  _,err=timelineStore().Append(in.SessionID,bunnytimeline.Entry{
   Lane:"evidence",Action:"validate",State:"succeeded",Source:bunnytimeline.SourceTool,
   AssetID:"pyproof_"+hex.EncodeToString(digest[:8]),EvidenceSHA256:hex.EncodeToString(digest[:]),
  })
  if err!=nil{
   result.Meta=map[string]any{"timeline_warning":"proof capture succeeded but metadata timeline write failed"}
  }
 }
 return result
}
var _=errors.New
