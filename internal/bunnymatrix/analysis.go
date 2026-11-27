// Package bunnymatrix evaluates bounded, metadata-only cross-identity
// authorization observations. It neither sends requests nor verifies that
// caller-supplied evidence came from an actual target.
package bunnymatrix

import (
 "errors"
 "fmt"
 "regexp"
 "sort"
 "strings"
)

const (
 MaxObservations = 256
 MaxCases = 64
 Anonymous = "anonymous"
)
var safeID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var shaPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var signals = map[string]bool{"present":true,"absent":true,"unknown":true}
var sources = map[string]bool{"operator_supplied":true,"captured_har":true,"synthetic_fixture":true}

type Observation struct {
 ID string `json:"id"`
 CaseID string `json:"case_id"`
 EndpointID string `json:"endpoint_id"`
 ResourceSHA256 string `json:"resource_sha256"`
 OwnerID string `json:"owner_id"`
 ActorID string `json:"actor_id"`
 Method string `json:"method"`
 Status int `json:"status"`
 MarkerSignal string `json:"marker_signal"`
 MarkerSHA256 string `json:"marker_sha256,omitempty"`
 EvidenceSHA256 string `json:"evidence_sha256"`
 Source string `json:"source"`
}
type CaseResult struct {
 CaseID string `json:"case_id"`
 EndpointID string `json:"endpoint_id"`
 ResourceSHA256 string `json:"resource_sha256"`
 Status string `json:"status"`
 OwnerObservations int `json:"owner_observations"`
 PeerObservations int `json:"peer_observations"`
 AnonymousObservations int `json:"anonymous_observations"`
 MatchingPeerIDs []string `json:"matching_peer_ids"`
 AnonymousMarkerMatch bool `json:"anonymous_marker_match"`
 HasDeniedAnonymousControl bool `json:"has_denied_anonymous_control"`
 NeedsIndependentReproduction bool `json:"needs_independent_reproduction"`
 Notes string `json:"notes"`
}
type Report struct {
 TotalObservations int `json:"total_observations"`
 TotalCases int `json:"total_cases"`
 Outcomes map[string]int `json:"outcomes"`
 Cases []CaseResult `json:"cases"`
 Disclaimer string `json:"disclaimer"`
}
func validObservation(o Observation) error {
 for _,id:=range []string{o.ID,o.CaseID,o.EndpointID,o.OwnerID,o.ActorID} {
  if !safeID.MatchString(id) {return errors.New("invalid observation, case, endpoint or identity ID")}
 }
 if o.OwnerID==Anonymous {return errors.New("anonymous cannot own a test resource")}
 if !shaPattern.MatchString(o.ResourceSHA256)||!shaPattern.MatchString(o.EvidenceSHA256) {
  return errors.New("resource and evidence digests must be lowercase SHA-256")
 }
 if (o.Method!="GET"&&o.Method!="HEAD"&&o.Method!="POST") || o.Status<100||o.Status>599 {
  return errors.New("unsupported method or HTTP status")
 }
 if !signals[o.MarkerSignal]||!sources[o.Source] {return errors.New("invalid marker signal or source")}
 if o.MarkerSignal=="present" {
  if !shaPattern.MatchString(o.MarkerSHA256){return errors.New("present marker requires a nonsecret marker digest")}
 } else if o.MarkerSHA256!="" {return errors.New("marker digest may only be supplied for a present marker")}
 return nil
}
type groupedCase struct {
 key string
 caseID,endpointID,resourceHash,owner,method string
 records []Observation
}
func Analyze(observations []Observation) (Report,error) {
 if len(observations)==0||len(observations)>MaxObservations {
  return Report{},fmt.Errorf("requires 1..%d observations",MaxObservations)
 }
 seen:=map[string]bool{}
 groups:=map[string]*groupedCase{}
 for _,o:=range observations {
  if err:=validObservation(o);err!=nil{return Report{},fmt.Errorf("observation %q: %w",o.ID,err)}
  if seen[o.ID]{return Report{},fmt.Errorf("duplicate observation ID %q",o.ID)}
  seen[o.ID]=true
  k:=strings.Join([]string{o.CaseID,o.EndpointID,o.ResourceSHA256},"|")
  g:=groups[k]
  if g==nil {
   g=&groupedCase{key:k,caseID:o.CaseID,endpointID:o.EndpointID,resourceHash:o.ResourceSHA256,owner:o.OwnerID,method:o.Method}
   groups[k]=g
  }else if g.owner!=o.OwnerID||g.method!=o.Method {
   return Report{},errors.New("inconsistent method or declared owner for same test resource")
  }
  g.records=append(g.records,o)
 }
 if len(groups)>MaxCases{return Report{},fmt.Errorf("too many cases: %d",len(groups))}
 keys:=make([]string,0,len(groups))
 for k:=range groups{keys=append(keys,k)}
 sort.Strings(keys)
 output:=Report{TotalObservations:len(observations),TotalCases:len(groups),Cases:[]CaseResult{},Outcomes:map[string]int{},
  Disclaimer:"All results are hypotheses from caller-supplied observations; a matching benign test marker and 2xx response do NOT prove authorization bypass. Verify using independent, scope-approved reproduction and negative controls. No live requests were made."}
 for _,k:=range keys {
  g:=groups[k]
  r:=evaluate(g)
  output.Cases=append(output.Cases,r)
  output.Outcomes[r.Status]++
 }
 return output,nil
}
func isSuccess(status int) bool {return status>=200&&status<300}
func isDenied(status int) bool {return status==401||status==403}
func evaluate(g *groupedCase) CaseResult {
 r:=CaseResult{CaseID:g.caseID,EndpointID:g.endpointID,ResourceSHA256:g.resourceHash,
  MatchingPeerIDs:[]string{},NeedsIndependentReproduction:false}
 ownerMarker:=map[string]bool{}
 ownerProofs:=map[string]bool{}
 for _,o:=range g.records{
  if o.ActorID==g.owner {
   r.OwnerObservations++
   if isSuccess(o.Status)&&o.MarkerSignal=="present"{
    ownerMarker[o.MarkerSHA256]=true
    ownerProofs[o.EvidenceSHA256]=true
   }
  }else if o.ActorID==Anonymous {
   r.AnonymousObservations++
   if isDenied(o.Status){r.HasDeniedAnonymousControl=true}
  }else{r.PeerObservations++}
 }
 if len(ownerMarker)==0 {
  r.Status="owner_baseline_missing"
  r.Notes="Owner needs a successful observation containing the expected benign test-resource marker."
  return r
 }
 peers:=map[string]map[string]bool{}
 for _,o:=range g.records {
  if o.ActorID==g.owner || o.MarkerSignal!="present" || !isSuccess(o.Status){continue}
  if !ownerMarker[o.MarkerSHA256]{continue}
  if o.ActorID==Anonymous{r.AnonymousMarkerMatch=true;continue}
  if peers[o.ActorID]==nil{peers[o.ActorID]=map[string]bool{}}
  peers[o.ActorID][o.EvidenceSHA256]=true
 }
 for actor:=range peers{r.MatchingPeerIDs=append(r.MatchingPeerIDs,actor)}
 sort.Strings(r.MatchingPeerIDs)
 if r.AnonymousMarkerMatch {
  r.Status="anonymous_resource_access_candidate"
  r.NeedsIndependentReproduction=true
  r.Notes="Anonymous response contains the owner test marker. Confirm intended resource visibility and re-run with controlled accounts."
  return r
 }
 if len(r.MatchingPeerIDs)>0 {
  corroborated:=len(ownerProofs)>=2&&r.HasDeniedAnonymousControl
  for _,evidence:=range peers {
   if len(evidence)<2{corroborated=false}
  }
  if corroborated {
   r.Status="repeated_cross_identity_candidate"
   r.Notes="Repeated owner and peer marker matches with denied anonymous control; evidence is still not independently attested."
  }else{
   r.Status="cross_identity_candidate"
   r.Notes="Peer response includes the same benign owner test marker. Repeat independently and obtain anonymous negative control."
  }
  r.NeedsIndependentReproduction=true
  return r
 }
 if r.PeerObservations==0 {
  r.Status="peer_control_missing"
  r.Notes="No peer-account observations for this resource."
  return r
 }
 allDenied:=true
 for _,o:=range g.records{
  if o.ActorID!=g.owner&&o.ActorID!=Anonymous&&!isDenied(o.Status) {allDenied=false}
 }
 if allDenied {
  r.Status="peer_access_denied"
  r.Notes="Observed peers were denied; this is not proof that all authorization paths are protected."
 }else {
  r.Status="inconclusive"
  r.Notes="No matching owner marker observed for peers; 2xx status alone is insufficient."
 }
 return r
}
