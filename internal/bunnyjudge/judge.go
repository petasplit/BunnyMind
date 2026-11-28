// Package bunnyjudge independently re-evaluates already captured,
 // operator-authorized Python evidence without sending network requests.
 // A judge verdict never establishes exploitability or security impact.
package bunnyjudge

import (
 "bytes"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strconv"
 "time"

 "github.com/enowdev/antares/internal/bunnyaudit"
 "github.com/enowdev/antares/internal/bunnyartifact"
)

type Case struct {
 SampleID string `json:"sample_id"`
 Kind string `json:"kind"`
 Persona string `json:"persona"`
 Method string `json:"method"`
 Path string `json:"path"`
}
type Plan struct{
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 Marker string `json:"marker"`
 Cases []Case `json:"cases"`
}
type Sample struct{
 SampleID string `json:"sample_id"`
 Kind string `json:"kind"`
 Persona string `json:"persona"`
 Status int `json:"status"`
 RequestSHA256 string `json:"request_sha256"`
 ResponseSHA256 string `json:"response_sha256"`
 MarkerPresent bool `json:"marker_present"`
 Truncated bool `json:"truncated"`
 ObservedAt string `json:"observed_at"`
 ContentSHA256 string `json:"content_sha256"`
 RequestB64 string `json:"request_b64"`
 ResponseB64 string `json:"response_b64"`
}
type Transcript struct{
 Version int `json:"version"`
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 Observations []Sample `json:"observations"`
}
type Verdict struct{
 Version int `json:"version"`
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 AuditResult string `json:"audit_result"`
 EvidenceSHA256 string `json:"evidence_sha256"`
 CandidateSamples int `json:"candidate_samples"`
 ControlSamples int `json:"control_samples"`
 ValidCandidates int `json:"valid_candidates"`
 ValidControls int `json:"valid_controls"`
 DistinctPersonas int `json:"distinct_personas"`
 Classification string `json:"classification"`
 ImpactVerified bool `json:"impact_verified"`
 Checks []string `json:"checks"`
 Limitations []string `json:"limitations"`
}
func digest(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
func loadBounded(path string,max int)([]byte,error){
 info,err:=os.Lstat(path)
 if err!=nil{return nil,err}
 if !info.Mode().IsRegular()||info.Size()<1||info.Size()>int64(max){
  return nil,errors.New("judge requires a bounded, regular evidence file")
 }
 return os.ReadFile(path)
}
func JudgeRun(folder string,key []byte)(Verdict,error){
 if len(key)!=32{return Verdict{},errors.New("OS-owned 32-byte vault key required")}
 audit,err:=bunnyaudit.VerifyRun(folder,key)
 if err!=nil{return Verdict{},fmt.Errorf("independent evidence review rejected unauthenticated bundle: %w",err)}
 planRaw,err:=loadBounded(filepath.Join(folder,"plan.json"),64*1024)
 if err!=nil{return Verdict{},err}
 var p Plan
 if err:=json.Unmarshal(planRaw,&p);err!=nil{return Verdict{},err}
 if p.EngagementID!=audit.EngagementID||p.RunID!=audit.RunID||
  len(p.Cases)<2||len(p.Cases)>96||len(p.Marker)<3||len(p.Marker)>128{
  return Verdict{},errors.New("invalid or mismatched approved evidence plan")
 }
 raw,err:=bunnyartifact.Open(folder,"transcript","http_proof",key)
 if err!=nil{return Verdict{},fmt.Errorf("encrypted evidence could not be independently authenticated: %w",err)}
 var t Transcript
 if err:=json.Unmarshal(raw,&t);err!=nil{return Verdict{},err}
 if t.Version!=1||t.EngagementID!=p.EngagementID||t.RunID!=p.RunID||
  len(t.Observations)!=len(p.Cases){return Verdict{},errors.New("captured cases differ from sealed plan")}
 v:=Verdict{Version:1,EngagementID:p.EngagementID,RunID:p.RunID,
  AuditResult:audit.Result,EvidenceSHA256:digest(raw),Checks:[]string{
   "six saved proof files authenticated with local MAC",
   "AES-GCM transcript decrypted and SHA-256 matched",
   "each captured request and response independently rehashed",
   "candidate marker checked against response bytes, not report assertions",
   "negative controls and repeated samples independently reviewed",
  },Limitations:[]string{
   "This second parser is independent of the script generator, but runs on the same machine and key; it is not an independent security authority.",
   "Matching markers and HTTP status do not demonstrate confidentiality, integrity or availability impact.",
   "No network requests, third-party confirmations or cross-account permission checks are performed by this judge.",
  }}
 personas:=map[string]bool{}
 seen:=map[string]bool{}
 for i,obs:=range t.Observations{
  want:=p.Cases[i]
  if obs.SampleID!=want.SampleID||obs.Kind!=want.Kind||obs.Persona!=want.Persona||
   obs.SampleID==""||seen[obs.SampleID]{
   return Verdict{},fmt.Errorf("sample %d identity differs from approved plan",i+1)
  }
  seen[obs.SampleID]=true
  personas[obs.Persona]=true
  if want.Kind!="candidate"&&want.Kind!="control"{return Verdict{},errors.New("unknown control class")}
  if want.Method!="GET"&&want.Method!="HEAD"{return Verdict{},errors.New("unsupported proof method")}
  rq,err:=base64.StdEncoding.Strict().DecodeString(obs.RequestB64)
  if err!=nil||len(rq)<10||len(rq)>8192||digest(rq)!=obs.RequestSHA256{
   return Verdict{},fmt.Errorf("sample %d request integrity mismatch",i+1)
  }
  res,err:=base64.StdEncoding.Strict().DecodeString(obs.ResponseB64)
  if err!=nil||len(res)<15||len(res)>70000||digest(res)!=obs.ResponseSHA256{
   return Verdict{},fmt.Errorf("sample %d response integrity mismatch",i+1)
  }
  if !bytes.HasPrefix(rq,[]byte(want.Method+" "+want.Path+" HTTP/1.1\r\n")){
   return Verdict{},fmt.Errorf("sample %d request destination differs from plan",i+1)
  }
  headerEnd:=bytes.Index(res,[]byte("\r\n\r\n"))
  lineEnd:=bytes.Index(res,[]byte("\r\n"))
  if headerEnd<0||lineEnd<0||obs.Status<100||obs.Status>599||
   !bytes.HasPrefix(res[:lineEnd],[]byte("HTTP/1.1 "+strconv.Itoa(obs.Status)+" ")){
   return Verdict{},fmt.Errorf("sample %d response format/status mismatch",i+1)
  }
  body:=res[headerEnd+4:]
  if digest(body)!=obs.ContentSHA256{return Verdict{},fmt.Errorf("sample %d body differs from captured hash",i+1)}
  hasMarker:=bytes.Contains(body,[]byte(p.Marker))
  if hasMarker!=obs.MarkerPresent{return Verdict{},fmt.Errorf("sample %d marker differs from captured bytes",i+1)}
  if _,err:=time.Parse(time.RFC3339,obs.ObservedAt);err!=nil{
   return Verdict{},fmt.Errorf("sample %d invalid capture timestamp",i+1)
  }
  if want.Kind=="candidate"{
   v.CandidateSamples++
   if obs.Status>=200&&obs.Status<300&&hasMarker&&!obs.Truncated&&!bytes.Contains(rq,[]byte(p.Marker)){v.ValidCandidates++}
  }else{
   v.ControlSamples++
   if obs.Status>=200&&obs.Status<500&&!hasMarker&&!obs.Truncated{v.ValidControls++}
  }
 }
 v.DistinctPersonas=len(personas)
 v.Classification="insufficient_or_inconclusive_evidence"
 if v.CandidateSamples>=2&&v.ControlSamples>=2&&
  v.CandidateSamples==v.ValidCandidates&&v.ControlSamples==v.ValidControls{
  v.Classification="replicated_observation_needs_independent_impact_review"
 }
 // Never convert a captured marker into an assertion of exploitable impact.
 v.ImpactVerified=false
 return v,nil
}
