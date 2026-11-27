// Package bunnyfix compares two cryptographically signed authorization-lab
// assessments. It never tests arbitrary websites or applies a code fix.
package bunnyfix

import (
 "crypto/ed25519"
 "errors"

 "github.com/enowdev/antares/internal/bunnyauthz"
)

type Pair struct {
 BeforePlan bunnyauthz.Plan `json:"before_plan"`
 BeforeCapture bunnyauthz.Capture `json:"before_capture"`
 AfterPlan bunnyauthz.Plan `json:"after_plan"`
 AfterCapture bunnyauthz.Capture `json:"after_capture"`
}
type Result struct {
 Outcome string `json:"outcome"`
 BeforeOutcome string `json:"before_outcome"`
 AfterOutcome string `json:"after_outcome"`
 BeforeSignedSamples int `json:"before_signed_samples"`
 AfterSignedSamples int `json:"after_signed_samples"`
 BeforeOwnerDigests []string `json:"before_owner_receipt_sha256"`
 BeforeForeignDigests []string `json:"before_foreign_receipt_sha256"`
 AfterOwnerDigests []string `json:"after_owner_receipt_sha256"`
 AfterForeignDigests []string `json:"after_foreign_receipt_sha256"`
 Reason string `json:"reason"`
 Disclaimer string `json:"disclaimer"`
}
// Compare authenticates both signed, loopback-only observations, then applies
// a deterministic comparison. Same engagement/case/path/marker, different run
// IDs are required; separate loopback ports may represent before/after builds.
func Compare(pub ed25519.PublicKey,p Pair)(Result,error){
 if len(pub)!=ed25519.PublicKeySize{return Result{},errors.New("trusted recorder public key is required")}
 if err:=bunnyauthz.Validate(p.BeforePlan);err!=nil{return Result{},err}
 if err:=bunnyauthz.Validate(p.AfterPlan);err!=nil{return Result{},err}
 b,a:=p.BeforePlan,p.AfterPlan
 if b.EngagementID!=a.EngagementID || b.CaseID!=a.CaseID ||
  b.ResourcePath!=a.ResourcePath || b.Marker!=a.Marker {
  return Result{},errors.New("before/after case, engagement, resource path and marker must match")
 }
 if b.RunID==a.RunID {return Result{},errors.New("independent before/after run IDs required")}
 before,err:=bunnyauthz.Assess(pub,b,p.BeforeCapture)
 if err!=nil{return Result{},err}
 after,err:=bunnyauthz.Assess(pub,a,p.AfterCapture)
 if err!=nil{return Result{},err}
 out:=Result{
  Outcome:"inconclusive",
  BeforeOutcome:before.Outcome,AfterOutcome:after.Outcome,
  BeforeSignedSamples:before.SignedSamples,AfterSignedSamples:after.SignedSamples,
  BeforeOwnerDigests:before.OwnerReceiptDigests,
  BeforeForeignDigests:before.ForeignReceiptDigests,
  AfterOwnerDigests:after.OwnerReceiptDigests,
  AfterForeignDigests:after.ForeignReceiptDigests,
  Disclaimer:"This is a signed before/after comparison of local synthetic fixtures. It does not prove production remediation, independent deployment identity, or exploit impact.",
 }
 switch {
 case before.Outcome=="cross_persona_marker_observed_in_lab" && after.Outcome=="cross_persona_denied_in_lab":
  out.Outcome="remediation_observed_in_lab"
  out.Reason="foreign synthetic persona lost marker access while owner and anonymous controls stayed valid"
 case before.Outcome=="cross_persona_denied_in_lab" && after.Outcome=="cross_persona_marker_observed_in_lab":
  out.Outcome="regression_observed_in_lab"
  out.Reason="foreign synthetic persona gained marker access after change"
 case before.Outcome=="cross_persona_marker_observed_in_lab" && after.Outcome=="cross_persona_marker_observed_in_lab":
  out.Outcome="unchanged_exposure_in_lab"
  out.Reason="the synthetic marker exposure persisted across the two signed runs"
 case before.Outcome=="cross_persona_denied_in_lab" && after.Outcome=="cross_persona_denied_in_lab":
  out.Outcome="unchanged_denial_in_lab"
  out.Reason="cross-persona denial was maintained across the two signed runs"
 default:
  out.Reason="at least one signed run failed its owner/anonymous/cross-user controls"
 }
 return out,nil
}
