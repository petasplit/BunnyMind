package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/enowdev/antares/internal/bunnytimeline"
	"github.com/enowdev/antares/internal/config"
)

// explorationTimelineTool exposes verified replay of a bounded activity
// journal. Agent-provided entries are unverified declarations; only dedicated
// trusted tool integration may record tool_observed traffic.
type explorationTimelineTool struct{}
func (explorationTimelineTool) Name() string { return "exploration_timeline" }
func (explorationTimelineTool) Description() string {
	return "Append a structured, unverified agent activity/exploration/auth/evidence event "+
		"or read the tamper-evident session timeline. Keeps task and parent-step links "+
		"and hashed evidence references. Raw URLs, headers, cookies, request bodies, "+
		"passwords and free-form notes are not accepted. Only scoped_read itself records "+
		"tool_observed traffic. No network activity."
}
func (explorationTimelineTool) RequiresApproval() bool { return false }
func (explorationTimelineTool) Schema() map[string]any {
	return schema(map[string]any{
		"action":propEnum("Timeline operation.","append","list","status"),
		"lane":propEnum("Timeline lane or optional list filter.","activity","exploration","traffic","auth","evidence"),
		"event_action":propEnum("Structured action for append.","inspect","map","test","verify","retest","escalate","handoff","sign_in","rotate","logout","report"),
		"state":propEnum("Observed state (not a proof assertion).","queued","running","succeeded","failed","blocked","needs_review"),
		"task_id":prop("string","Optional safe task identifier (no sensitive data)."),
		"parent_seq":prop("integer","Optional prior timeline sequence number for a branch."),
		"asset_id":prop("string","Optional non-sensitive asset identifier, not a URL."),
		"evidence_sha256":prop("string","Optional SHA-256 of separately saved, sanitized evidence."),
		"after_seq":propDefault("integer","For list: show events after this sequence.",0),
		"limit":propDefault("integer","For list: 1..100 events.",30),
	},"action")
}
var timelineManagers = struct {
	sync.Mutex
	byRoot map[string]*bunnytimeline.Store
}{byRoot:map[string]*bunnytimeline.Store{}}
func timelineStore() *bunnytimeline.Store {
	root:=filepath.Clean(config.Path("bunnymind","timeline"))
	timelineManagers.Lock();defer timelineManagers.Unlock()
	if m,ok:=timelineManagers.byRoot[root];ok{return m}
	m:=bunnytimeline.New(root)
	timelineManagers.byRoot[root]=m
	return m
}
func (explorationTimelineTool) Execute(_ context.Context,in Input) Result {
	if strings.TrimSpace(in.SessionID)=="" {return Errorf("timeline requires an active session")}
	if len(in.Args)==0||len(in.Args)>4096{return Errorf("timeline arguments must be 1..4096 bytes")}
	var args struct {
		Action string `json:"action"`
		Lane string `json:"lane"`
		EventAction string `json:"event_action"`
		State string `json:"state"`
		TaskID string `json:"task_id"`
		ParentSeq uint64 `json:"parent_seq"`
		AssetID string `json:"asset_id"`
		EvidenceSHA256 string `json:"evidence_sha256"`
		AfterSeq uint64 `json:"after_seq"`
		Limit int `json:"limit"`
	}
	d:=json.NewDecoder(bytes.NewReader(in.Args))
	d.DisallowUnknownFields()
	if err:=d.Decode(&args);err!=nil{return Errorf("invalid timeline arguments: %v",err)}
	var extra any
	if err:=d.Decode(&extra);err!=io.EOF{return Errorf("timeline accepts one JSON object")}
	store:=timelineStore()
	var out any
	var err error
	switch args.Action {
	case "append":
		if args.Lane=="traffic" {return Errorf("traffic events must come from an actual scoped_read, not the agent")}
		out,err=store.Append(in.SessionID,bunnytimeline.Entry{
			Lane:args.Lane,Action:args.EventAction,State:args.State,
			Source:bunnytimeline.SourceAgent,TaskID:args.TaskID,
			ParentSeq:args.ParentSeq,AssetID:args.AssetID,
			EvidenceSHA256:args.EvidenceSHA256,
		})
	case "list":
		if args.Limit==0{args.Limit=30}
		out,err=store.Read(in.SessionID,args.Lane,args.AfterSeq,args.Limit)
	case "status":
		out,err=store.Read(in.SessionID,"",0,1)
		if err==nil {out=out.(bunnytimeline.Page).Summary}
	default:
		return Errorf("unknown timeline operation")
	}
	if err!=nil{return Errorf("timeline operation rejected: %v",err)}
	b,err:=json.MarshalIndent(out,"","  ")
	if err!=nil{return Errorf("timeline encoding failed: %v",err)}
	return Text(string(b))
}
