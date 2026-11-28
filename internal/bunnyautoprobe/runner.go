package bunnyautoprobe

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyquota"
 "github.com/enowdev/antares/internal/bunnyscript"
)

type Round struct{
 Index int `json:"index"`
 RunID string `json:"run_id"`
 CandidatePathSHA256 string `json:"candidate_path_sha256"`
 ControlPathSHA256 string `json:"control_path_sha256"`
 ScriptSHA256 string `json:"script_sha256"`
 EvidenceSHA256 string `json:"evidence_sha256"`
 Outcome string `json:"outcome"`
 CandidateStatus []int `json:"candidate_status"`
 ControlStatus []int `json:"control_status"`
}
type CampaignResult struct{
 EngagementID string `json:"engagement_id"`
 CampaignID string `json:"campaign_id"`
 StartedAt string `json:"started_at"`
 EndedAt string `json:"ended_at"`
 Runs []Round `json:"runs"`
 RequestsUsed int `json:"requests_used"`
 Outcome string `json:"outcome"`
 StopReason string `json:"stop_reason"`
 Disclaimer string `json:"disclaimer"`
}
type Runner struct{ Proof bunnyscript.Runner }
func (r Runner) Execute(ctx context.Context,s Spec,policy bunnyguard.Policy)(CampaignResult,error){
 if err:=Validate(s,policy);err!=nil{return CampaignResult{},err}
 if r.Proof.Root==""{return CampaignResult{},errors.New("evidence vault destination required")}
 release,err:=bunnyquota.ExecutionLeaseShared(ctx,s.EngagementID)
 if err!=nil{return CampaignResult{},fmt.Errorf("adaptive Python execution denied: %w",err)}
 defer release()
 // Reserve the entire worst-case campaign request envelope *once* across
 // local processes. Individual sub-runs use that reservation and cannot
 // double-charge, nor can another concurrent worker overrun the budget.
 if _,err:=bunnyquota.ReserveShared(ctx,s.EngagementID,s.MaxRequests,policy.MaxNetworkCalls);err!=nil{
  return CampaignResult{},fmt.Errorf("shared campaign request budget denied: %w",err)
 }
 // This is a bounded online run, not a scheduled background operation.
 ctx,cancel:=context.WithTimeout(ctx,10*time.Minute)
 defer cancel()
 folder:=filepath.Join(r.Proof.Root,s.CampaignID)
 if err:=os.Mkdir(folder,0700);err!=nil{return CampaignResult{},err}
 cfg,err:=json.MarshalIndent(s,"","  ")
 if err!=nil{return CampaignResult{},err}
 if err:=os.WriteFile(filepath.Join(folder,"study.json"),cfg,0600);err!=nil{return CampaignResult{},err}
 proof:=r.Proof
 proof.Root=folder
 proof.BudgetReserved=true
 proof.ExecutionLeaseHeld=true
 result:=CampaignResult{EngagementID:s.EngagementID,CampaignID:s.CampaignID,
  StartedAt:time.Now().UTC().Format(time.RFC3339Nano),Runs:[]Round{},
  Outcome:"inconclusive",
  Disclaimer:"All HTTP observations are recorded with negative controls in operator-approved GET-only Python scripts. Reproduction by the same harness is not independent vulnerability verification, impact proof, or authority to exploit.",
 }
 index:=0
 pendingRepeat:=false
 for number:=0;number<s.MaxRounds&&result.RequestsUsed+4<=s.MaxRequests;number++{
  if err:=ctx.Err();err!=nil{return result,err}
  p:=PlanFor(s,number,index)
  if err:=bunnyscript.Validate(p,policy);err!=nil{return result,err}
  capture,err:=proof.Run(ctx,p,policy)
  if err!=nil{
   result.StopReason="capture_or_verification_failed"
   result.EndedAt=time.Now().UTC().Format(time.RFC3339Nano)
   _=r.persist(folder,result)
   return result,fmt.Errorf("round %d: private evidence capture failed: %w",number+1,err)
  }
  if err:=ValidateRoundResult(p,capture);err!=nil{
   return result,errors.New("Python evidence summary was not linked to the planned samples")
  }
  one:=Round{Index:number+1,RunID:p.RunID,
   CandidatePathSHA256:bunnyscript.SHA([]byte(p.Cases[0].Path)),
   ControlPathSHA256:bunnyscript.SHA([]byte(p.Cases[1].Path)),
   ScriptSHA256:capture.ScriptSHA256,EvidenceSHA256:capture.RawEvidenceSHA256,
   Outcome:capture.Outcome,CandidateStatus:[]int{},ControlStatus:[]int{},
  }
  for _,receipt:=range capture.Receipts{
   if receipt.Kind=="candidate"{one.CandidateStatus=append(one.CandidateStatus,receipt.Status)
   }else{one.ControlStatus=append(one.ControlStatus,receipt.Status)}
  }
  result.Runs=append(result.Runs,one)
  result.RequestsUsed+=4
  next,stop,reason:=NextIndex(s,index,capture,pendingRepeat)
  if stop{
   result.StopReason=reason
   if reason=="observation_replicated_needs_independent_impact_review"{
    // Do not mislabel a repeated response marker as an exploited issue.
    result.Outcome="replicated_observation_unverified"
   }
   break
  }
  pendingRepeat=capture.Outcome=="repeated_candidate_with_negative_controls"
  index=next
  result.StopReason=reason
 }
 if result.StopReason==""{
  result.StopReason="run_or_request_budget_exhausted"
 }
 result.EndedAt=time.Now().UTC().Format(time.RFC3339Nano)
 if err:=r.persist(folder,result);err!=nil{return result,err}
 return result,nil
}
func (r Runner) persist(folder string,result CampaignResult)error{
 report,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return err}
 if err:=os.WriteFile(filepath.Join(folder,"campaign.json"),report,0600);err!=nil{return err}
 var md strings.Builder
 fmt.Fprintf(&md,"# BunnyMind adaptive evidence campaign: %s\n\n",result.CampaignID)
 fmt.Fprintf(&md,"**Engagement:** %s  \n**Outcome:** %s  \n**Stop reason:** %s  \n**Requests:** %d\n\n",
  result.EngagementID,result.Outcome,result.StopReason,result.RequestsUsed)
 md.WriteString("## Runs with preserved Python source and encrypted HTTP responses\n\n")
 md.WriteString("| Run | Observation | Candidate status | Control status | Script SHA-256 | Evidence SHA-256 |\n|---|---|---|---|---|---|\n")
 for _,one:=range result.Runs{
  fmt.Fprintf(&md,"| %s | %s | %v | %v | %s | %s |\n",
   one.RunID,one.Outcome,one.CandidateStatus,one.ControlStatus,one.ScriptSHA256,one.EvidenceSHA256)
 }
 md.WriteString("\nEach run folder contains scenario.py, plan.json, validation.json, report.md and transcript.enc. The raw request/response records are encrypted in the OS-keyring-protected vault and must not be copied to public bug-bounty issues. The campaign establishes only repeated observations, not an independently confirmed vulnerability.\n")
 return os.WriteFile(filepath.Join(folder,"report.md"),[]byte(md.String()),0600)
}
