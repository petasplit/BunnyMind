package bunnybench

import (
 "crypto/ed25519"
 "errors"
 "fmt"
 "strings"

 "github.com/enowdev/antares/internal/bunnyreceipt"
)
// SignedStudy converts lab-signed observations to benchmark evidence gates.
// Model-reported claims cannot supply their own successful proof events.
type SignedStudy struct {
 EngagementID string `json:"engagement_id"`
 Manifest Manifest `json:"manifest"`
 Trials []SignedTrial `json:"trials"`
}
type SignedTrial struct {
 RunID string `json:"run_id"`
 Model string `json:"model"`
 DurationSeconds float64 `json:"duration_seconds,omitempty"`
 Reported []string `json:"reported"`
 Bundles []bunnyreceipt.Bundle `json:"bundles"`
}
// ScoreSignedStudy derives proof/control booleans exclusively from receipts
// authenticated with the pinned recorder public key. It never makes requests.
func ScoreSignedStudy(pub ed25519.PublicKey,s SignedStudy)(Result,error){
 if len(pub)!=ed25519.PublicKeySize{return Result{},errors.New("invalid recorder public key")}
 if strings.TrimSpace(s.EngagementID)==""{return Result{},errors.New("engagement identifier required")}
 known:=map[string]bool{}
 for _,c:=range s.Manifest.Cases{known[c.ID]=true}
 standard:=Study{Manifest:s.Manifest,Trials:[]Trial{}}
 for _,t:=range s.Trials{
  if strings.TrimSpace(t.RunID)==""{return Result{},errors.New("blank trial ID")}
  verifiedCases:=map[string]bool{}
  seenBundles:=map[string]bool{}
  for _,bundle:=range t.Bundles{
   if bundle.EngagementID!=s.EngagementID||bundle.RunID!=t.RunID{
    return Result{},fmt.Errorf("bundle is not tied to its trial %q",t.RunID)
   }
   if !known[bundle.CaseID]{return Result{},fmt.Errorf("unrecognized benchmark case %q",bundle.CaseID)}
   if seenBundles[bundle.CaseID]{return Result{},fmt.Errorf("case %q has multiple bundles in run %q",bundle.CaseID,t.RunID)}
   seenBundles[bundle.CaseID]=true
   summary,err:=bunnyreceipt.Verify(pub,bundle)
   if err!=nil{return Result{},fmt.Errorf("untrusted bundle for run %q case %q: %w",t.RunID,bundle.CaseID,err)}
   if summary.Assessment=="consistent-signed-observations"{verifiedCases[bundle.CaseID]=true}
  }
  proof,control:=[]string{},[]string{}
  for _,c:=range s.Manifest.Cases{
   if verifiedCases[c.ID]{
    proof=append(proof,c.ID)
    control=append(control,c.ID)
   }
  }
  standard.Trials=append(standard.Trials,Trial{
   RunID:t.RunID,Model:t.Model,DurationSeconds:t.DurationSeconds,
   ProofEvents:proof,PassedControls:control,Reported:t.Reported,
  })
 }
 result,err:=ScoreStudy(standard)
 if err!=nil{return Result{},err}
 result.Disclaimer="Scores depend on pinned Ed25519 signatures from a separately operated lab recorder. This authenticates who signed observations, not their truth or real-world vulnerability impact. No scanning or independent replay occurred in this scorer."
 return result,nil
}
