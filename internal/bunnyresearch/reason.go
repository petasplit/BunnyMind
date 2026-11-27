// Package bunnyresearch evaluates bounded, structured experiment outcomes.
// It does not create exploit payloads, perform WAF evasion, or send requests.
package bunnyresearch

import (
 "crypto/rand"
 "encoding/hex"
 "errors"
 "fmt"
 "regexp"
 "sort"
)

const MaxObservations=64
var safeID=regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
var sha256Hex=regexp.MustCompile(`^[0-9a-f]{64}$`)
var acceptedKinds=map[string]bool{
 "authorization":true,"input_handling":true,
 "server_execution":true,"business_logic":true,
}
var acceptedRoles=map[string]bool{"baseline":true,"control":true,"candidate":true}
var acceptedSignals=map[string]bool{
 "normal":true,"denied":true,"marker":true,
 "intermediary_block":true,"transport_error":true,"server_error":true,
}
type Observation struct {
 ID string `json:"id"`
 Role string `json:"role"`
 Signal string `json:"signal"`
 TreatmentSHA256 string `json:"treatment_sha256"`
 EvidenceSHA256 string `json:"evidence_sha256"`
}
type Study struct {
 CaseID string `json:"case_id"`
 Kind string `json:"kind"`
 Budget int `json:"budget"`
 Observations []Observation `json:"observations"`
}
type Decision struct {
 CaseID string `json:"case_id"`
 Classification string `json:"classification"`
 NextAction string `json:"next_action"`
 Reason string `json:"reason"`
 RemainingBudget int `json:"remaining_budget"`
 Samples int `json:"samples"`
 UniqueCandidateTreatments int `json:"unique_candidate_treatments"`
 RepeatedCandidateTreatments int `json:"repeated_candidate_treatments"`
 IndependentCandidateEvidence int `json:"independent_candidate_evidence"`
 Disclaimer string `json:"disclaimer"`
}
func validate(s Study)error{
 if !safeID.MatchString(s.CaseID){return errors.New("case ID must be 1..80 safe characters")}
 if !acceptedKinds[s.Kind]{return errors.New("unsupported hypothesis category")}
 if s.Budget<1||s.Budget>MaxObservations{return errors.New("budget must be 1..64")}
 if len(s.Observations)>s.Budget{return errors.New("provided observations exceed declared budget")}
 seen:=map[string]bool{}
 for _,o:=range s.Observations{
  if !safeID.MatchString(o.ID)||seen[o.ID]{return fmt.Errorf("observation ID invalid or duplicated: %q",o.ID)}
  seen[o.ID]=true
  if !acceptedRoles[o.Role]||!acceptedSignals[o.Signal]{return errors.New("invalid experiment role or outcome signal")}
  if !sha256Hex.MatchString(o.TreatmentSHA256)||!sha256Hex.MatchString(o.EvidenceSHA256){
   return errors.New("treatment and evidence must be SHA-256 digests")
  }
 }
 return nil
}
// Analyze classifies caller-provided observations and suggests the *kind* of
// the next safe experiment. It does not authenticate the supplied digests or
// generate exploit strings, WAF bypasses, or network instructions.
func Analyze(s Study)(Decision,error){
 if err:=validate(s);err!=nil{return Decision{},err}
 d:=Decision{CaseID:s.CaseID,Classification:"inconclusive",
  NextAction:"collect_baseline",
  Samples:len(s.Observations),RemainingBudget:s.Budget-len(s.Observations),
  Disclaimer:"Only caller-provided observation classifications were evaluated. Hashes are not attested. The decision is not an exploit verification or authority to send network requests.",
 }
 baselines,controls,candidates:=[]Observation{},[]Observation{},[]Observation{}
 for _,o:=range s.Observations{
  switch o.Role {
  case "baseline":baselines=append(baselines,o)
  case "control":controls=append(controls,o)
  case "candidate":candidates=append(candidates,o)
  }
 }
 distinctTreatments:=map[string]bool{}
 candidateRepeats:=0
 for _,o:=range candidates{
  if distinctTreatments[o.TreatmentSHA256]{candidateRepeats++}
  distinctTreatments[o.TreatmentSHA256]=true
 }
 d.UniqueCandidateTreatments=len(distinctTreatments)
 d.RepeatedCandidateTreatments=candidateRepeats
 if len(baselines)==0{
  d.Reason="no repeatable application baseline has been supplied"
  return finish(d),nil
 }
 goodBaseline:=false
 for _,b:=range baselines{if b.Signal=="normal"||b.Signal=="denied"{goodBaseline=true}}
 if !goodBaseline{
  d.NextAction="diagnose_baseline"
  d.Reason="baseline itself is blocked, failing, or showing unexpected content"
  return finish(d),nil
 }
 if len(controls)==0{
  d.NextAction="collect_negative_control"
  d.Reason="a negative control is required before interpreting candidate effects"
  return finish(d),nil
 }
 validControl:=false
 for _,o:=range controls{
  if o.Signal=="marker"{
   d.Classification="invalid_control"
   d.NextAction="investigate_control_contamination"
   d.Reason="negative control shows the purported indicator"
   return finish(d),nil
  }
  if o.Signal=="normal"||o.Signal=="denied"{validControl=true}
 }
 if !validControl{
  d.NextAction="repair_control"
  d.Reason="negative control failed or was blocked before reaching the application"
  return finish(d),nil
 }
 if len(candidates)==0{
  d.NextAction="run_first_bounded_candidate"
  d.Reason="baseline and control exist but no candidate observation has been supplied"
  return finish(d),nil
 }
 blocked,errorSignal,markerCount:=0,0,0
 distinctEvidence:=map[string]bool{}
 for _,o:=range candidates{
  switch o.Signal {
  case "intermediary_block":blocked++
  case "transport_error","server_error":errorSignal++
  case "marker":markerCount++;distinctEvidence[o.EvidenceSHA256]=true
  }
 }
 d.IndependentCandidateEvidence=len(distinctEvidence)
 if markerCount>=2&&len(distinctEvidence)>=2{
  d.Classification="unverified_candidate_signal"
  d.NextAction="request_independent_reproduction"
  d.Reason="two candidate observations report an indicator with distinct evidence digests; signed replay and impact validation are still required"
 }else if markerCount>0{
  d.Classification="single_candidate_signal"
  d.NextAction="repeat_with_independent_control"
  d.Reason="marker observed but repeatability and evidence independence remain insufficient"
 }else if blocked>0&&blocked==len(candidates){
  d.Classification="intermediary_blocked_not_tested"
  d.NextAction="classify_intermediary_response"
  d.Reason="every candidate was blocked upstream; the application hypothesis was not evaluated"
 }else if errorSignal>0{
  d.Classification="inconclusive"
  d.NextAction="restore_transport_and_baseline"
  d.Reason="candidate transport/server errors prevent security conclusions"
 }else if candidateRepeats>=2{
  d.Classification="unconfirmed"
  d.NextAction="form_different_hypothesis"
  d.Reason="same treatment was repeatedly tried without supporting evidence; repeating it is low-information"
 }else{
  d.Classification="unconfirmed"
  d.NextAction="choose_new_information_gain_test"
  d.Reason="candidate controls show no reproducible indicator; consider a different, explicitly authorized non-destructive hypothesis"
 }
 return finish(d),nil
}
func finish(d Decision)Decision{
 if d.RemainingBudget==0&&d.NextAction!="request_independent_reproduction"{
  d.NextAction="stop_and_review_budget"
  d.Reason+="; observation budget is exhausted"
 }
 return d
}
// Canary returns a random harmless test identifier, NOT an exploit payload.
// It is highly unlikely to repeat, but global novelty is not guaranteed.
func Canary()(string,error){
 b:=make([]byte,16)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return "BUNNY_BENIGN_"+hex.EncodeToString(b),nil
}
func DistinctStrategies(s Study)([]string,error){
 if err:=validate(s);err!=nil{return nil,err}
 out:=[]string{}
 seen:=map[string]bool{}
 for _,o:=range s.Observations{
  if o.Role=="candidate"{seen[o.TreatmentSHA256]=true}
 }
 for k:=range seen{out=append(out,k)}
 sort.Strings(out)
 return out,nil
}
