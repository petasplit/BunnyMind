package bunnybrowserflow

import (
 "crypto/sha256"
 "encoding/hex"
 "sort"
 "strconv"
)

// NextCheck is an evidence-linked recommendation, never an automated
// exploit request or a finding. A validated engagement task runner may
// consider these in a subsequent separately authorized work phase.
type NextCheck struct{
 ID string `json:"id"`
 Category string `json:"category"`
 Priority int `json:"priority"`
 EvidenceDigest string `json:"evidence_sha256"`
 Rationale string `json:"rationale"`
 RequiresReview bool `json:"requires_review"`
}
func followupID(category,hash string)string{
 sum:=sha256.Sum256([]byte(category+"|"+hash))
 return "next_"+hex.EncodeToString(sum[:8])
}
// AnalyzeAuthNextChecks proposes bounded, non-destructive next investigation
// phases based only on actual browser-reported metadata and completed test
// identities. It never turns a status code into a confirmed vulnerability.
func AnalyzeAuthNextChecks(result Result)[]NextCheck{
 checks:=map[string]NextCheck{}
 add:=func(category string,priority int,digest,rationale string){
  if len(digest)!=64{
   sum:=sha256.Sum256([]byte(category+"|"+strconv.Itoa(result.Actors)))
   digest=hex.EncodeToString(sum[:])
  }
  if _,exists:=checks[category];exists{return}
  checks[category]=NextCheck{ID:followupID(category,digest),Category:category,
   Priority:priority,EvidenceDigest:digest,Rationale:rationale,RequiresReview:true}
 }
 if result.Actors>1{
  add("cross_identity_authorization",5,"","Multiple isolated test personas completed authentication; compare only operator-owned seeded resources with the authorization matrix.")
 }
 if result.StepsCompleted>0{
  add("session_lifecycle",4,"","Authentication was observed; check logout, token renewal and session isolation with approved test identities.")
 }
 if len(result.Traffic)==0{
  add("telemetry_gap",3,"","No correlated browser traffic metadata was captured; collect independent controls before drawing conclusions.")
 }
 seenCodes:=map[string]bool{}
 for _,t:=range result.Traffic {
  if t.Outcome=="failed"{
   add("transport_recovery",4,t.ReceiptSHA256,"Browser requests failed; investigate scope, transport and intermediary responses before retrying.")
  }
  if t.Status>=500&&t.Status<=599{
   add("server_error_reproduction",4,t.ReceiptSHA256,"An application error occurred. Investigate with a bounded baseline and independent retest.")
  }
  if t.Status==401||t.Status==403{
   add("auth_boundary_controls",4,t.ReceiptSHA256,"An authorization denial was observed; compare test-persona and anonymous controls without assuming a bypass.")
  }
  if t.Status>=300&&t.Status<400{
   add("redirect_boundary_review",2,t.ReceiptSHA256,"A redirect occurred; check in-scope authentication transitions and scope fidelity.")
  }
  if t.Method=="POST"&&!seenCodes[t.PathSHA256]{
   seenCodes[t.PathSHA256]=true
   add("state_change_review",3,t.ReceiptSHA256,"A state-changing authenticated endpoint was observed; review workflow and ownership using approved controls.")
  }
 }
 out:=make([]NextCheck,0,len(checks))
 for _,v:=range checks{out=append(out,v)}
 sort.Slice(out,func(i,j int)bool{
  if out[i].Priority!=out[j].Priority{return out[i].Priority>out[j].Priority}
  return out[i].Category<out[j].Category
 })
 if len(out)>8{out=out[:8]}
 return out
}
