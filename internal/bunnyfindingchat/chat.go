// Package bunnyfindingchat provides source-grounded, persistent discussion
// of an engagement's recorded findings. It never executes security probes.
package bunnyfindingchat

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "sync"

 "github.com/enowdev/antares/internal/findings"
)
var safeFinding=regexp.MustCompile(`^F-[0-9]{3,6}$`)
var unsafeInput=regexp.MustCompile(`(?i)(bearers+S+|passwords*[:=]|tokens*[:=]|secrets*[:=]|cookies*[:=])`)
type Turn struct {
 Role string `json:"role"`
 Text string `json:"text"`
 EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
}
type Conversation struct {
 Session string `json:"session"`
 FindingID string `json:"finding_id"`
 Title string `json:"title"`
 Severity string `json:"severity"`
 Status string `json:"status"`
 Turns []Turn `json:"turns"`
}
type Store struct{
 root string
 mu sync.Mutex
}
func New(root string)*Store{return &Store{root:root}}
func (s *Store) path(session,id string)string{
 h:=sha256.Sum256([]byte(session))
 return filepath.Join(s.root,hex.EncodeToString(h[:12])+"-"+id+".json")
}
func check(session,id string)error{
 if len(session)<1||len(session)>160||!safeFinding.MatchString(id){return errors.New("invalid conversation identity")}
 return nil
}
func (s *Store) Load(session,id string)([]Turn,error){
 if err:=check(session,id);err!=nil{return nil,err}
 s.mu.Lock();defer s.mu.Unlock()
 return s.load(session,id)
}
func (s *Store) load(session,id string)([]Turn,error){
 b,err:=os.ReadFile(s.path(session,id))
 if os.IsNotExist(err){return []Turn{},nil}
 if err!=nil{return nil,err}
 if len(b)>65536{return nil,errors.New("conversation exceeded storage budget")}
 var turns []Turn
 if json.Unmarshal(b,&turns)!=nil{return nil,errors.New("conversation storage corrupt")}
 return turns,nil
}
func (s *Store) Append(session,id,question string,f findings.Finding)([]Turn,error){
 if err:=check(session,id);err!=nil{return nil,err}
 question=strings.TrimSpace(question)
 if len(question)<2||len(question)>500||strings.ContainsAny(question,"\r\n")||unsafeInput.MatchString(question){
  return nil,errors.New("question must be 2..500 characters without secrets or control characters")
 }
 response,digest:=Answer(f,question)
 s.mu.Lock();defer s.mu.Unlock()
 turns,err:=s.load(session,id);if err!=nil{return nil,err}
 turns=append(turns,Turn{Role:"user",Text:question},Turn{Role:"assistant",Text:response,EvidenceSHA256:digest})
 if len(turns)>40{turns=turns[len(turns)-40:]}
 if err:=os.MkdirAll(s.root,0700);err!=nil{return nil,err}
 data,err:=json.MarshalIndent(turns,"","  ");if err!=nil{return nil,err}
 tmp:=s.path(session,id)+".tmp"
 if err:=os.WriteFile(tmp,data,0600);err!=nil{return nil,err}
 if err:=os.Rename(tmp,s.path(session,id));err!=nil{return nil,err}
 return turns,nil
}
func Answer(f findings.Finding,question string)(string,string){
 digest:=sha256.Sum256([]byte(f.ID+"|"+f.Title+"|"+f.Reproduce+"|"+f.PoC+"|"+f.Impact))
 hash:=hex.EncodeToString(digest[:])
 has:=func(s string)string{if strings.TrimSpace(s)==""{return "missing"};return "present"}
 q:=strings.ToLower(question)
 var response string
 switch{
 case strings.Contains(q,"impact")||strings.Contains(q,"risk")||strings.Contains(q,"severity"):
  response=fmt.Sprintf("Recorded severity: %s; triage status: %s. Documented impact: %s. This is a ledger assertion, not an independently verified exploit.",f.Severity,f.Status,has(f.Impact))
 case strings.Contains(q,"retest")||strings.Contains(q,"verify")||strings.Contains(q,"proof")||strings.Contains(q,"poc"):
  response=fmt.Sprintf("Evidence checklist: reproduction steps %s; PoC %s; impact %s. Retest only the authorized test resources with owner and denied controls, repeat the observation, and compare separate evidence digests.",has(f.Reproduce),has(f.PoC),has(f.Impact))
 case strings.Contains(q,"fix")||strings.Contains(q,"patch")||strings.Contains(q,"remediat"):
  response=fmt.Sprintf("Recorded remediation: %s. Request a scoped patch review, run a regression fixture, and retain before/after negative controls. A source change alone does not verify a fix.",has(f.Remediation))
 case strings.Contains(q,"duplicate")||strings.Contains(q,"status"):
  response=fmt.Sprintf("Current triage status: %s. Duplicate reference: %s. Compare the root cause and separately retained evidence rather than titles alone.",f.Status,has(f.DuplicateOf))
 default:
  response=fmt.Sprintf("Finding %s has severity %s and status %s. Recorded proof: %s; reproduction: %s; impact: %s. Ask about impact, proof, independent retesting, remediation or duplicate status. This response uses this engagement's finding ledger only.",f.ID,f.Severity,f.Status,has(f.PoC),has(f.Reproduce),has(f.Impact))
 }
 return response,hash
}
