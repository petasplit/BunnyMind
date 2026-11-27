// Package bunnyauthz performs bounded, synthetic cross-user access checks
// against numeric loopback lab fixtures and validates signed observations.
// It is not a general website scanner or production credential handler.
package bunnyauthz

import (
 "context"
 "crypto/ed25519"
 "encoding/json"
 "errors"
 "fmt"
 "strings"

 "github.com/enowdev/antares/internal/bunnylab"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)

const OwnerActor="owner"
const ForeignActor="foreign"
const AnonymousActor="anonymous"

type Plan struct{
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 CaseID string `json:"case_id"`
 Origin string `json:"origin"`
 ResourcePath string `json:"resource_path"`
 Marker string `json:"marker"`
}
// Tokens are provided by the separate trusted test recorder, never written
// to a plan, the agent workspace, signed observation or result.
type Tokens struct{
 Owner string
 Foreign string
}
type Capture struct{
 OwnerBundle bunnyreceipt.Bundle `json:"owner_bundle"`
 CrossUserBundle bunnyreceipt.Bundle `json:"cross_user_bundle"`
}
type Assessment struct{
 Outcome string `json:"outcome"`
 OwnerAccessObserved bool `json:"owner_access_observed"`
 ForeignMarkerObserved bool `json:"foreign_marker_observed"`
 ForeignDeniedObserved bool `json:"foreign_denied_observed"`
 SignedSamples int `json:"signed_samples"`
 OwnerReceiptDigests []string `json:"owner_receipt_sha256"`
 ForeignReceiptDigests []string `json:"foreign_receipt_sha256"`
 Reasons []string `json:"reasons"`
 Disclaimer string `json:"disclaimer"`
}
func (p Plan) labPlan(actor,caseSuffix string)bunnylab.Plan{
 caseID:=p.CaseID+"_"+caseSuffix
 samples:=[]bunnylab.Probe{
  {SampleID:"positive_1",Kind:"positive",Path:p.ResourcePath,Persona:actor},
  {SampleID:"control_1",Kind:"control",Path:p.ResourcePath,Persona:AnonymousActor},
  {SampleID:"positive_2",Kind:"positive",Path:p.ResourcePath,Persona:actor},
  {SampleID:"control_2",Kind:"control",Path:p.ResourcePath,Persona:AnonymousActor},
 }
 return bunnylab.Plan{
  EngagementID:p.EngagementID,RunID:p.RunID,CaseID:caseID,
  Origin:p.Origin,Marker:p.Marker,Probes:samples,
 }
}
func Validate(p Plan)error{
 // The owner/foreign test must address one canonical resource; query strings
 // would risk mixing secrets or input parameters into the signed comparisons.
 if strings.ContainsAny(p.ResourcePath,"?#"){return errors.New("authorization test resource path cannot contain query or fragment")}
 if err:=bunnylab.Validate(p.labPlan(OwnerActor,"owner"));err!=nil{return fmt.Errorf("owner plan: %w",err)}
 if err:=bunnylab.Validate(p.labPlan(ForeignActor,"foreign"));err!=nil{return fmt.Errorf("cross-user plan: %w",err)}
 return nil
}
func validToken(t string)bool{
 return len(t)>=8 && len(t)<=512 && !strings.ContainsAny(t," \t\r\n")
}
// Record captures real lab responses from an explicitly loopback-only
// destination. The two synthetic bearer tokens must be distinct.
func Record(ctx context.Context,p Plan,priv ed25519.PrivateKey,tokens Tokens)(Capture,error){
 if err:=Validate(p);err!=nil{return Capture{},err}
 if !validToken(tokens.Owner)||!validToken(tokens.Foreign)||tokens.Owner==tokens.Foreign{
  return Capture{},errors.New("distinct synthetic owner/foreign tokens are required")
 }
 secrets:=map[string]string{OwnerActor:tokens.Owner,ForeignActor:tokens.Foreign}
 owner,err:=bunnylab.CaptureWithPersonas(ctx,p.labPlan(OwnerActor,"owner"),priv,secrets)
 if err!=nil{return Capture{},fmt.Errorf("owner observations: %w",err)}
 foreign,err:=bunnylab.CaptureWithPersonas(ctx,p.labPlan(ForeignActor,"foreign"),priv,secrets)
 if err!=nil{return Capture{},fmt.Errorf("cross-user observations: %w",err)}
 return Capture{OwnerBundle:owner,CrossUserBundle:foreign},nil
}
func denied(status int)bool{return status==401||status==403||status==404}
func validPersonaSamples(bundle bunnyreceipt.Bundle,actor string)bool{
 positives,controls:=0,0
 for _,r:=range bundle.Receipts{
  o:=r.Observation
  if o.Kind=="positive"{
   positives++
   if o.Actor!=actor||o.Method!="GET"||o.MarkerInRequest{return false}
  }else if o.Kind=="control"{
   controls++
   if o.Actor!=AnonymousActor||o.Method!="GET"||o.MarkerInRequest{return false}
   if !denied(o.ResponseStatus)||o.MarkerPresent{return false}
  }else{return false}
 }
 return positives>=2&&controls>=2
}
func allPositives(bundle bunnyreceipt.Bundle,expectPresent bool)bool{
 count:=0
 for _,r:=range bundle.Receipts{
  o:=r.Observation
  if o.Kind!="positive"{continue}
  count++
  if expectPresent{
   if o.ResponseStatus!=200||!o.MarkerPresent{return false}
  }else{
   if !denied(o.ResponseStatus)||o.MarkerPresent{return false}
  }
 }
 return count>=2
}
// Assess authenticates receipts with a pinned key and checks two controls:
// legitimate owner access and denied anonymous access. It distinguishes
// a marker observed by a foreign synthetic account from a denied response.
// The result is only a local-lab observation, not CVSS or a live exploit PoC.
func Assess(pub ed25519.PublicKey,p Plan,c Capture)(Assessment,error){
 if err:=Validate(p);err!=nil{return Assessment{},err}
 if c.OwnerBundle.EngagementID!=p.EngagementID||c.OwnerBundle.RunID!=p.RunID||
  c.OwnerBundle.CaseID!=p.CaseID+"_owner"||
  c.CrossUserBundle.EngagementID!=p.EngagementID||c.CrossUserBundle.RunID!=p.RunID||
  c.CrossUserBundle.CaseID!=p.CaseID+"_foreign"{
  return Assessment{},errors.New("receipt bundle does not match the declared engagement, run and case")
 }
 owner,err:=bunnyreceipt.Verify(pub,c.OwnerBundle)
 if err!=nil{return Assessment{},fmt.Errorf("owner receipt authentication failed: %w",err)}
 cross,err:=bunnyreceipt.Verify(pub,c.CrossUserBundle)
 if err!=nil{return Assessment{},fmt.Errorf("foreign receipt authentication failed: %w",err)}
 if !validPersonaSamples(c.OwnerBundle,OwnerActor)||!validPersonaSamples(c.CrossUserBundle,ForeignActor){
  return Assessment{},errors.New("authenticated sample role/status controls are inconsistent")
 }
 marker:=bunnyreceipt.Dig(p.Marker)
 for _,bundle:=range []bunnyreceipt.Bundle{c.OwnerBundle,c.CrossUserBundle}{
  for _,r:=range bundle.Receipts{
   if r.Observation.Origin!=p.Origin||r.Observation.MarkerSHA256!=marker{
    return Assessment{},errors.New("signed samples use unexpected origin or marker")
   }
  }
 }
 out:=Assessment{
  Outcome:"inconclusive",OwnerReceiptDigests:owner.ReceiptsSHA256,
  ForeignReceiptDigests:cross.ReceiptsSHA256,
  SignedSamples:owner.AuthenticatedReceipts+cross.AuthenticatedReceipts,
  Reasons:[]string{},
  Disclaimer:"Signed, loopback-only lab behavior; not independent proof of production authorization failure. The fixture and token-owner mapping are operator-controlled.",
 }
 out.OwnerAccessObserved=owner.Assessment=="consistent-signed-observations"&&
  allPositives(c.OwnerBundle,true)
 if !out.OwnerAccessObserved{
  out.Reasons=append(out.Reasons,"legitimate synthetic owner access was not established")
  return out,nil
 }
 if cross.Assessment=="consistent-signed-observations"&&
  allPositives(c.CrossUserBundle,true){
  out.ForeignMarkerObserved=true
  out.Outcome="cross_persona_marker_observed_in_lab"
  out.Reasons=append(out.Reasons,"foreign synthetic account saw the owner's marker twice while anonymous controls were denied")
 }else if allPositives(c.CrossUserBundle,false){
  out.ForeignDeniedObserved=true
  out.Outcome="cross_persona_denied_in_lab"
  out.Reasons=append(out.Reasons,"foreign synthetic account and anonymous controls received denied responses")
 }else{
  out.Reasons=append(out.Reasons,"cross-persona observations were inconsistent or incomplete")
 }
 return out,nil
}
// SummaryJSON emits only digests and statuses, not bearer tokens or raw
// response bodies. It is suitable for an offline lab test artifact.
func SummaryJSON(a Assessment)([]byte,error){return json.MarshalIndent(a,"","  ")}
