package bunnybrowserflow

import (
 "testing"
)
func TestAdaptiveNextChecksEvidenceDrivenAndBounded(t *testing.T){
 result:=Result{
  Actors:2,StepsCompleted:4,
  Traffic:[]TrafficReceipt{
   {Actor:"owner",Method:"POST",PathSHA256:"aaaa",Status:200,ReceiptSHA256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",Outcome:"responded"},
   {Actor:"peer",Method:"GET",PathSHA256:"bbbb",Status:403,ReceiptSHA256:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",Outcome:"responded"},
   {Actor:"owner",Method:"GET",PathSHA256:"cccc",Status:503,ReceiptSHA256:"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",Outcome:"responded"},
   {Actor:"owner",Method:"GET",PathSHA256:"dddd",Status:0,ReceiptSHA256:"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",Outcome:"failed"},
  },
 }
 checks:=AnalyzeAuthNextChecks(result)
 if len(checks)<5||len(checks)>8{t.Fatalf("unexpected count %d",len(checks))}
 found:=map[string]bool{}
 for _,c:=range checks{
  found[c.Category]=true
  if !c.RequiresReview||len(c.EvidenceDigest)!=64{t.Fatalf("missing review/evidence: %+v",c)}
 }
 for _,key:=range []string{"cross_identity_authorization","session_lifecycle","auth_boundary_controls","server_error_reproduction","transport_recovery","state_change_review"}{
  if !found[key]{t.Fatalf("missing grounded next check %s: %+v",key,checks)}
 }
 again:=AnalyzeAuthNextChecks(result)
 for i:=range checks{if checks[i].ID!=again[i].ID{t.Fatal("non-deterministic ranking")}}
}
func TestNextChecksDoNotInventIssuesFromStatusAlone(t *testing.T){
 result:=Result{Actors:1,StepsCompleted:1,Traffic:[]TrafficReceipt{{Method:"GET",Status:200,PathSHA256:"a",Outcome:"responded"}}}
 checks:=AnalyzeAuthNextChecks(result)
 for _,v:=range checks{
  if v.Category=="cross_identity_authorization"||v.Category=="server_error_reproduction"||v.Category=="auth_boundary_controls"{
   t.Fatalf("invented cross-account or server error from 200: %+v",v)
  }
 }
}
