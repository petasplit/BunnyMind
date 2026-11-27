// Package bunnyblackboard shares bounded observations across agent sessions
// in one declared engagement. It never executes security tests.
package bunnyblackboard

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strings"
 "sync"
 "time"
)
const (MaxEntries=256; MaxListing=50; StateOpen="open"; StateReproduction="needs_reproduction"; StateRejected="rejected")
var (
 idPattern=regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
 hashPattern=regexp.MustCompile(`^[0-9a-f]{64}$`)
 secretPattern=regexp.MustCompile(`(?i)(authorization\s*:|bearer\s+|api[_-]?key\s*[:=]|password\s*[:=]|session[_-]?cookie\s*[:=]|token\s*[:=]|secret\s*[:=])`)
 kinds=map[string]bool{"asset":true,"observation":true,"hypothesis":true,"task_hint":true,"retest":true}
 sources=map[string]bool{"captured_http":true,"source_inventory":true,"operator":true,"model_inference":true}
 reasons=map[string]bool{"crosscheck":true,"duplicate":true,"stale":true,"missing_evidence":true}
)
type Submission struct {
 ID string `json:"id"`
 Kind string `json:"kind"`
 AssetID string `json:"asset_id,omitempty"`
 Label string `json:"label"`
 Source string `json:"source"`
 EvidenceHash string `json:"evidence_sha256"`
}
type Record struct {
 Submission
 State string `json:"state"`
 AuthorRef string `json:"author_ref"`
 ReviewerRef string `json:"reviewer_ref,omitempty"`
 ReviewReason string `json:"review_reason,omitempty"`
 CreatedAt time.Time `json:"created_at"`
 ReviewedAt time.Time `json:"reviewed_at,omitempty"`
}
type Board struct {
 Version int `json:"version"`
 EngagementID string `json:"engagement_id"`
 Revision uint64 `json:"revision"`
 UpdatedAt time.Time `json:"updated_at"`
 Records []Record `json:"records"`
}
type Summary struct {
 EngagementRef string `json:"engagement_ref"`
 Revision uint64 `json:"revision"`
 Count int `json:"count"`
 ByKind map[string]int `json:"by_kind"`
 ByState map[string]int `json:"by_state"`
 Records []Record `json:"records"`
 Disclaimer string `json:"disclaimer"`
}
type Store struct {Root string;Mu sync.Mutex;Now func()time.Time}
func New(root string)*Store{return &Store{Root:root,Now:time.Now}}
func hash(s string)string{h:=sha256.Sum256([]byte(s));return hex.EncodeToString(h[:])}
func (s *Store) now()time.Time{if s.Now!=nil{return s.Now().UTC()};return time.Now().UTC()}
func (s *Store) path(engagement string)(string,error){
 if strings.TrimSpace(engagement)==""||len(engagement)>128{return "",errors.New("engagement ID required, max 128 chars")}
 return filepath.Join(s.Root,hash(engagement)+".json"),nil
}
func safeLabel(v string)bool{
 return strings.TrimSpace(v)==v&&v!=""&&len(v)<=160&&!strings.ContainsAny(v,"\r\n\x00")&&!secretPattern.MatchString(v)
}
func validateSubmission(v Submission)error{
 if !idPattern.MatchString(v.ID)||(v.AssetID!=""&&!idPattern.MatchString(v.AssetID)){return errors.New("IDs must be alphanumeric/underscore/hyphen, length 1..64")}
 if !kinds[v.Kind]||!sources[v.Source]{return errors.New("unsupported kind or provenance source")}
 if !safeLabel(v.Label){return errors.New("invalid/secret-like short label")}
 if !hashPattern.MatchString(v.EvidenceHash){return errors.New("lowercase 64-character SHA256 evidence digest required")}
 return nil
}
func validateRecord(r Record)error{
 if err:=validateSubmission(r.Submission);err!=nil{return err}
 if !hashPattern.MatchString(r.AuthorRef)||r.CreatedAt.IsZero(){return errors.New("invalid author/timestamp")}
 switch r.State{
 case StateOpen:
  if r.ReviewerRef!=""||r.ReviewReason!=""||!r.ReviewedAt.IsZero(){return errors.New("open record has review data")}
 case StateReproduction,StateRejected:
  if !hashPattern.MatchString(r.ReviewerRef)||r.ReviewerRef==r.AuthorRef||!reasons[r.ReviewReason]||r.ReviewedAt.IsZero(){return errors.New("invalid independent review")}
 default:return errors.New("unknown review state")
 }
 return nil
}
func (s *Store) read(engagement string)(Board,error){
 path,err:=s.path(engagement);if err!=nil{return Board{},err}
 data,err:=os.ReadFile(path)
 if os.IsNotExist(err){return Board{Version:1,EngagementID:engagement,Records:[]Record{}},nil}
 if err!=nil{return Board{},err}
 var b Board
 if err:=json.Unmarshal(data,&b);err!=nil{return Board{},fmt.Errorf("blackboard JSON corrupt: %w",err)}
 if b.Version!=1||b.EngagementID!=engagement||len(b.Records)>MaxEntries{return Board{},errors.New("blackboard invalid version/engagement/size")}
 ids:=map[string]bool{}
 for _,r:=range b.Records{
  if ids[r.ID]{return Board{},errors.New("duplicate persisted record ID")}
  ids[r.ID]=true
  if err:=validateRecord(r);err!=nil{return Board{},fmt.Errorf("record %s invalid: %w",r.ID,err)}
 }
 return b,nil
}
func (s *Store) write(engagement string,b Board)error{
 path,err:=s.path(engagement);if err!=nil{return err}
 if err:=os.MkdirAll(s.Root,0700);err!=nil{return err}
 b.UpdatedAt=s.now()
 payload,err:=json.MarshalIndent(b,"","  ");if err!=nil{return err}
 f,err:=os.CreateTemp(s.Root,".blackboard-*");if err!=nil{return err}
 tmp:=f.Name();defer os.Remove(tmp)
 if err:=f.Chmod(0600);err!=nil{f.Close();return err}
 if _,err:=f.Write(append(payload,'\n'));err!=nil{f.Close();return err}
 if err:=f.Sync();err!=nil{f.Close();return err}
 if err:=f.Close();err!=nil{return err}
 return os.Rename(tmp,path)
}
// RecordSubmission is idempotent; same ID with different data fails closed.
func (s *Store) RecordSubmission(engagement,session string,v Submission)(Record,bool,error){
 s.Mu.Lock();defer s.Mu.Unlock()
 if strings.TrimSpace(session)==""{return Record{},false,errors.New("origin session required")}
 if err:=validateSubmission(v);err!=nil{return Record{},false,err}
 b,err:=s.read(engagement);if err!=nil{return Record{},false,err}
 for _,old:=range b.Records{
  if old.ID!=v.ID{continue}
  if old.Submission==v{return old,false,nil}
  return Record{},false,errors.New("record ID already contains different data")
 }
 if len(b.Records)>=MaxEntries{return Record{},false,errors.New("board entry budget exhausted")}
 item:=Record{Submission:v,State:StateOpen,AuthorRef:hash(session),CreatedAt:s.now()}
 b.Records=append(b.Records,item);b.Revision++
 if err:=s.write(engagement,b);err!=nil{return Record{},false,err}
 return item,true,nil
}
// Review is performed by a different session and does not verify a finding.
func (s *Store) Review(engagement,reviewer,id,verdict,reason string)(Record,error){
 s.Mu.Lock();defer s.Mu.Unlock()
 if strings.TrimSpace(reviewer)==""{return Record{},errors.New("reviewer session required")}
 if verdict!=StateReproduction&&verdict!=StateRejected{return Record{},errors.New("review can only request reproduction or reject")}
 if !reasons[reason]{return Record{},errors.New("unknown controlled review reason")}
 b,err:=s.read(engagement);if err!=nil{return Record{},err}
 for i:=range b.Records{
  r:=&b.Records[i]
  if r.ID!=id{continue}
  if r.State!=StateOpen{return Record{},errors.New("review is immutable")}
  if r.AuthorRef==hash(reviewer){return Record{},errors.New("self-review denied")}
  r.State=verdict;r.ReviewerRef=hash(reviewer);r.ReviewReason=reason;r.ReviewedAt=s.now()
  b.Revision++;output:=*r
  if err:=s.write(engagement,b);err!=nil{return Record{},err}
  return output,nil
 }
 return Record{},errors.New("record not found")
}
func (s *Store) Summary(engagement string,limit int)(Summary,error){
 s.Mu.Lock();defer s.Mu.Unlock()
 if limit<0||limit>MaxListing{return Summary{},errors.New("limit must be 0..50")}
 b,err:=s.read(engagement);if err!=nil{return Summary{},err}
 out:=Summary{EngagementRef:hash(engagement),Revision:b.Revision,Count:len(b.Records),ByKind:map[string]int{},ByState:map[string]int{},Records:[]Record{},
 Disclaimer:"User/agent supplied evidence digests are not authenticated. A review may request independent reproduction; it is never verification."}
 for _,r:=range b.Records{out.ByKind[r.Kind]++;out.ByState[r.State]++}
 if limit>0{
  items:=append([]Record(nil),b.Records...)
  sort.Slice(items,func(i,j int)bool{return items[i].ID<items[j].ID})
  if len(items)>limit{items=items[:limit]}
  out.Records=items
 }
 return out,nil
}
