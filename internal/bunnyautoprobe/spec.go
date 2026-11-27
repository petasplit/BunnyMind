// Package bunnyautoprobe turns an authorized endpoint inventory into
// repeatedly executed Python evidence studies. It never interprets a marker
// as proof of exploitation or invents out-of-scope URLs.
package bunnyautoprobe

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyscript"
)

const MaxCandidates=12
const MaxRounds=8

// A scope owner supplies *only* permitted test-owned paths. The adaptive
// planner decides which candidate/control pairing to execute and when to
// repeat it. The model cannot turn arbitrary Python source into a tool call.
type Spec struct {
 EngagementID string `json:"engagement_id"`
 CampaignID string `json:"campaign_id"`
 Origin string `json:"origin"`
 Marker string `json:"marker"`
 CandidatePaths []string `json:"candidate_paths"`
 NegativeControlPaths []string `json:"negative_control_paths"`
 CandidatePersona string `json:"candidate_persona,omitempty"`
 ControlPersona string `json:"control_persona,omitempty"`
 MaxRounds int `json:"max_rounds"`
 MaxRequests int `json:"max_requests"`
 MinIntervalMS int `json:"min_interval_ms"`
}
func Load(raw []byte,policy bunnyguard.Policy)(Spec,error){
 if len(raw)==0||len(raw)>32768{return Spec{},errors.New("adaptive spec must be 1..32 KiB")}
 dec:=json.NewDecoder(bytes.NewReader(raw))
 dec.DisallowUnknownFields()
 var s Spec
 if err:=dec.Decode(&s);err!=nil{return Spec{},err}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return Spec{},errors.New("adaptive spec must be exactly one object")}
 if err:=Validate(s,policy);err!=nil{return Spec{},err}
 return s,nil
}
func Validate(s Spec,policy bunnyguard.Policy)error{
 if !bunnyscript.ValidRunID(s.CampaignID)||s.EngagementID!=policy.EngagementID{
  return errors.New("campaign identifier or engagement mismatch")
 }
 if len(s.CampaignID)>35{return errors.New("campaign ID must leave space for round suffix")}
 if len(s.CandidatePaths)==0||len(s.CandidatePaths)>MaxCandidates||
 len(s.NegativeControlPaths)==0||len(s.NegativeControlPaths)>MaxCandidates{
  return errors.New("adaptive study requires 1..12 approved candidate and negative-control paths")
 }
 if s.MaxRounds<1||s.MaxRounds>MaxRounds||s.MaxRequests<4*s.MaxRounds||
  s.MaxRequests>policy.MaxNetworkCalls||s.MaxRequests>96{
  return errors.New("adaptive round and request budgets exceed approved limits")
 }
 if s.MinIntervalMS<policy.MinIntervalMS||s.MinIntervalMS>5000{
  return errors.New("adaptive pacing violates the engagement")
 }
 seen:=map[string]bool{}
 for _,path:=range append(append([]string(nil),s.CandidatePaths...),s.NegativeControlPaths...){
  if seen[path]{return errors.New("candidate and negative-control paths must be distinct")}
  seen[path]=true
 }
 p:=bunnyscript.Plan{EngagementID:s.EngagementID,RunID:s.CampaignID+"-r01",
  Origin:s.Origin,Marker:s.Marker,MinIntervalMS:s.MinIntervalMS,
  Cases:makeCases(s,0),
 }
 if err:=bunnyscript.Validate(p,policy);err!=nil{return fmt.Errorf("invalid candidate inventory: %w",err)}
 for _,path:=range s.CandidatePaths{
  p.Cases[0].Path=path
  p.Cases[2].Path=path
  if err:=bunnyscript.Validate(p,policy);err!=nil{return fmt.Errorf("unapproved candidate path: %w",err)}
 }
 for _,path:=range s.NegativeControlPaths{
  p.Cases=makeCases(s,0)
  p.Cases[1].Path=path
  p.Cases[3].Path=path
  if err:=bunnyscript.Validate(p,policy);err!=nil{return fmt.Errorf("unapproved control path: %w",err)}
 }
 return nil
}
func makeCases(s Spec,index int)[]bunnyscript.Case{
 candidate:=s.CandidatePaths[index%len(s.CandidatePaths)]
 control:=s.NegativeControlPaths[index%len(s.NegativeControlPaths)]
 return []bunnyscript.Case{
  {SampleID:"candidate_first",Kind:"candidate",Persona:s.CandidatePersona,Method:"GET",Path:candidate},
  {SampleID:"control_first",Kind:"control",Persona:s.ControlPersona,Method:"GET",Path:control},
  {SampleID:"candidate_repeat",Kind:"candidate",Persona:s.CandidatePersona,Method:"GET",Path:candidate},
  {SampleID:"control_repeat",Kind:"control",Persona:s.ControlPersona,Method:"GET",Path:control},
 }
}
func PlanFor(s Spec,round,index int)bunnyscript.Plan{
 return bunnyscript.Plan{EngagementID:s.EngagementID,
  RunID:fmt.Sprintf("%s-r%02d",s.CampaignID,round+1),Origin:s.Origin,
  Marker:s.Marker,MinIntervalMS:s.MinIntervalMS,Cases:makeCases(s,index)}
}
func ValidateRoundResult(p bunnyscript.Plan,result bunnyscript.EvidenceSummary)error{
 if result.RunID!=p.RunID||result.EngagementID!=p.EngagementID||
  result.Cases!=4||len(result.Receipts)!=4||
  result.RawEvidenceSHA256==""||result.ScriptSHA256==""{
  return errors.New("incomplete authenticated Python round")
 }
 for i,got:=range result.Receipts{
  expected:=p.Cases[i]
  if got.SampleID!=expected.SampleID||got.Persona!=expected.Persona||
   got.Kind!=expected.Kind||got.RequestSHA256==""||got.ResponseSHA256==""{
   return errors.New("Python response does not correspond to the planned test identity and sample")
  }
 }
 return nil
}
// This decision has no exploit execution authority. It either repeats an
// observation on the same owner-controlled resource, examines another
// preapproved resource, or stops.
func NextIndex(s Spec,current int,summary bunnyscript.EvidenceSummary,
 repeated bool)(index int,stop bool,reason string){
 if summary.Outcome=="repeated_candidate_with_negative_controls"{
  if repeated{return current,true,"observation_replicated_needs_independent_impact_review"}
  return current,false,"repeat_same_candidate_with_fresh_capture"
 }
 if current+1>=len(s.CandidatePaths){
  return current,true,"all_selected_candidates_inconclusive"
 }
 return current+1,false,"change_candidate_after_inconclusive_controls"
}
var _=strings.TrimSpace
