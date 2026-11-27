// Package bunnytimeline stores a metadata-only, tamper-evident exploration
// timeline. It neither runs scans nor independently verifies caller claims.
package bunnytimeline

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	MaxEvents = 10000
	MaxPage = 100
	maxLine = 4096
	SourceAgent = "agent_declared"
	SourceTool = "tool_observed"
)
var safeID = regexp.MustCompile("^[A-Za-z0-9_-]{1,64}$")
var digest = regexp.MustCompile("^[a-f0-9]{64}$")
var lanes = map[string]bool{"activity":true,"exploration":true,"traffic":true,"auth":true,"evidence":true}
var actions = map[string]bool{"inspect":true,"map":true,"test":true,"verify":true,"retest":true,"escalate":true,"handoff":true,"sign_in":true,"rotate":true,"logout":true,"request":true,"report":true}
var states = map[string]bool{"queued":true,"running":true,"succeeded":true,"failed":true,"blocked":true,"needs_review":true}
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is structured metadata only: no body, headers, request payloads,
// credentials, raw URLs, operator notes or arbitrary free text are accepted.
type Entry struct {
	Lane string `json:"lane"`
	Action string `json:"action"`
	State string `json:"state"`
	Source string `json:"source"`
	TaskID string `json:"task_id,omitempty"`
	ParentSeq uint64 `json:"parent_seq,omitempty"`
	AssetID string `json:"asset_id,omitempty"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
	HTTPMethod string `json:"http_method,omitempty"`
	HTTPStatus int `json:"http_status,omitempty"`
	Bytes int `json:"bytes,omitempty"`
	Truncated bool `json:"truncated,omitempty"`
	Origin string `json:"origin,omitempty"`
}
type Event struct {
	Entry
	Seq uint64 `json:"seq"`
	RecordedAt time.Time `json:"recorded_at"`
	PrevSHA256 string `json:"prev_sha256"`
	SHA256 string `json:"sha256"`
}
type Summary struct {
	Total int `json:"total"`
	LastSHA256 string `json:"last_sha256"`
	ByLane map[string]int `json:"by_lane"`
	ByState map[string]int `json:"by_state"`
	IntegrityOK bool `json:"integrity_ok"`
	Disclaimer string `json:"disclaimer"`
}
type Page struct {
	Summary Summary `json:"summary"`
	Events []Event `json:"events"`
	NextAfterSeq uint64 `json:"next_after_seq"`
}
type Store struct {
	Root string
	Mu sync.Mutex
	Now func() time.Time
}
func New(root string) *Store { return &Store{Root:root,Now:time.Now} }
func (s *Store) now() time.Time {
	if s.Now != nil { return s.Now().UTC() }
	return time.Now().UTC()
}
func (s *Store) path(session string) (string,error) {
	if strings.TrimSpace(session)=="" || len(session)>512 { return "",errors.New("session ID required (max 512 bytes)") }
	h:=sha256.Sum256([]byte(session))
	return filepath.Join(s.Root,hex.EncodeToString(h[:])+".jsonl"),nil
}
func Validate(e Entry) error {
	if !lanes[e.Lane] || !actions[e.Action] || !states[e.State] {
		return errors.New("unknown lane, action or state")
	}
	if e.Source!=SourceAgent && e.Source!=SourceTool {
		return errors.New("source must be agent_declared or tool_observed")
	}
	if e.TaskID!="" && !safeID.MatchString(e.TaskID) { return errors.New("invalid task ID") }
	if e.AssetID!="" && !safeID.MatchString(e.AssetID) { return errors.New("invalid asset ID") }
	if e.EvidenceSHA256!="" && !digest.MatchString(e.EvidenceSHA256) {
		return errors.New("invalid evidence digest")
	}
	if e.Action=="verify" && e.State=="succeeded" && e.EvidenceSHA256=="" {
		return errors.New("verification observation needs an evidence digest")
	}
	if e.Lane=="traffic" {
		if e.Source!=SourceTool || e.Action!="request" ||
		   (e.HTTPMethod!="GET" && e.HTTPMethod!="HEAD") ||
		   e.HTTPStatus<100 || e.HTTPStatus>599 || e.Bytes<0 || e.Bytes>65536 ||
		   e.EvidenceSHA256=="" || e.Origin=="" {
			return errors.New("traffic events require tool-observed bounded HTTP metadata")
		}
		u,err:=url.Parse(e.Origin)
		if err!=nil || u==nil || (u.Scheme!="http" && u.Scheme!="https") ||
		   u.Host=="" || u.User!=nil || u.Path!="" || u.RawQuery!="" || u.Fragment!="" {
			return errors.New("invalid HTTP origin")
		}
	} else if e.HTTPMethod!="" || e.HTTPStatus!=0 || e.Bytes!=0 ||
	          e.Truncated || e.Origin!="" {
		return errors.New("HTTP metadata only allowed on traffic events")
	}
	return nil
}
func eventHash(e Event) (string,error) {
	e.SHA256=""
	b,err:=json.Marshal(e)
	if err!=nil { return "",err }
	sum:=sha256.Sum256(b)
	return hex.EncodeToString(sum[:]),nil
}
func blankSummary() Summary {
	return Summary{LastSHA256:genesis,ByLane:map[string]int{},ByState:map[string]int{},
		IntegrityOK:true,Disclaimer:"Timeline metadata is not vulnerability proof. agent_declared events are not tool-attested; tool_observed events attest only to the named local tool operation, not a finding."}
}
func (s *Store) readLocked(session string) ([]Event,Summary,error) {
	path,err:=s.path(session);if err!=nil{return nil,Summary{},err}
	f,err:=os.Open(path)
	if os.IsNotExist(err){return []Event{},blankSummary(),nil}
	if err!=nil{return nil,Summary{},err}
	defer f.Close()
	r:=bufio.NewScanner(f)
	r.Buffer(make([]byte,4096),maxLine)
	events:=make([]Event,0)
	out:=blankSummary()
	for r.Scan() {
		if len(events)>=MaxEvents { return nil,Summary{},errors.New("timeline exceeds event budget") }
		var e Event
		if err:=json.Unmarshal(r.Bytes(),&e);err!=nil{return nil,Summary{},fmt.Errorf("corrupt event %d: %w",len(events)+1,err)}
		if err:=Validate(e.Entry);err!=nil{return nil,Summary{},fmt.Errorf("invalid event %d: %w",len(events)+1,err)}
		if e.Seq!=uint64(len(events)+1) || e.PrevSHA256!=out.LastSHA256 ||
		   e.RecordedAt.IsZero() || e.RecordedAt.Location()!=time.UTC ||
		   e.ParentSeq>=e.Seq && e.ParentSeq!=0 || !digest.MatchString(e.SHA256) {
			return nil,Summary{},fmt.Errorf("invalid event chain at seq %d",len(events)+1)
		}
		expected,err:=eventHash(e)
		if err!=nil||expected!=e.SHA256 {return nil,Summary{},fmt.Errorf("hash mismatch at seq %d",e.Seq)}
		events=append(events,e)
		out.Total++
		out.LastSHA256=e.SHA256
		out.ByLane[e.Lane]++
		out.ByState[e.State]++
	}
	if err:=r.Err();err!=nil{return nil,Summary{},err}
	return events,out,nil
}
// Append adds exactly one structured event and fsyncs its JSONL record.
// A broken hash chain blocks further append rather than silently repairing it.
func (s *Store) Append(session string,e Entry) (Event,error) {
	s.Mu.Lock();defer s.Mu.Unlock()
	if err:=Validate(e);err!=nil{return Event{},err}
	events,sum,err:=s.readLocked(session)
	if err!=nil{return Event{},err}
	if len(events)>=MaxEvents{return Event{},errors.New("timeline event budget exhausted")}
	if e.ParentSeq>uint64(len(events)){return Event{},errors.New("parent event does not exist")}
	v:=Event{Entry:e,Seq:uint64(len(events)+1),RecordedAt:s.now(),PrevSHA256:sum.LastSHA256}
	v.SHA256,err=eventHash(v)
	if err!=nil{return Event{},err}
	line,err:=json.Marshal(v)
	if err!=nil{return Event{},err}
	if len(line)>=maxLine{return Event{},errors.New("event exceeds maximum line size")}
	path,err:=s.path(session);if err!=nil{return Event{},err}
	if err:=os.MkdirAll(s.Root,0700);err!=nil{return Event{},err}
	f,err:=os.OpenFile(path,os.O_CREATE|os.O_WRONLY|os.O_APPEND,0600)
	if err!=nil{return Event{},err}
	if _,err=f.Write(append(line,'\n'));err!=nil{f.Close();return Event{},err}
	if err=f.Sync();err!=nil{f.Close();return Event{},err}
	if err=f.Close();err!=nil{return Event{},err}
	return v,nil
}
// Read verifies the entire chain before returning a bounded filtered page.
func (s *Store) Read(session,lane string,after uint64,limit int) (Page,error) {
	s.Mu.Lock();defer s.Mu.Unlock()
	if lane!="" && !lanes[lane]{return Page{},errors.New("invalid lane filter")}
	if limit<1||limit>MaxPage{return Page{},fmt.Errorf("limit must be 1..%d",MaxPage)}
	events,sum,err:=s.readLocked(session)
	if err!=nil{return Page{},err}
	page:=Page{Summary:sum,Events:[]Event{},NextAfterSeq:after}
	for _,e:=range events{
		if e.Seq<=after || (lane!=""&&e.Lane!=lane){continue}
		if len(page.Events)>=limit{break}
		page.Events=append(page.Events,e)
		page.NextAfterSeq=e.Seq
	}
	return page,nil
}
