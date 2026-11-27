package tools

import (
 "context"
 "encoding/json"
 "fmt"
 "path/filepath"
 "strings"
 "sync"

 "github.com/enowdev/antares/internal/bunnyharness"
 "github.com/enowdev/antares/internal/bunnytimeline"
 "github.com/enowdev/antares/internal/config"
)

// investigationBoardTool manages offline, durable, dependency-aware work
// without executing subprocesses or sending network requests.
type investigationBoardTool struct{}
func (investigationBoardTool) Name()string{return "investigation_board"}
func (investigationBoardTool) Description()string{
 return "Manage a bounded, restart-resumable investigation plan within this Antares session. "+
 "Actions: plan, claim, heartbeat, complete, fail, status. "+
 "Completion requires a SHA-256 digest of existing evidence but is NOT an independent verification. "+
 "Only records task metadata; does NOT execute a scan, tool or network call."
}
func (investigationBoardTool) RequiresApproval()bool{return false}
func (investigationBoardTool) Schema()map[string]any{
 return schema(map[string]any{
  "action":propEnum("Board operation.","plan","claim","heartbeat","complete","fail","status"),
  "tasks":map[string]any{
   "type":"array",
   "description":"For plan: bounded task list with unique IDs and dependencies.",
   "items":map[string]any{"type":"object","properties":map[string]any{
    "id":prop("string","Alphanumeric task ID, with underscore or hyphen."),
    "title":prop("string","Short description without secrets."),
    "kind":propEnum("Task type.","inventory","analysis","verification","review","report","remediation"),
    "priority":prop("integer","1..5, higher first."),
    "depends_on":map[string]any{"type":"array","items":map[string]any{"type":"string"}},
    "max_attempts":prop("integer","Retry budget 1..5."),
   },"required":[]string{"id","title","kind","priority","max_attempts"}},
  },
  "max_parallel":propDefault("integer","For plan: maximum simultaneous leased tasks, 1..8.",2),
  "lease_seconds":propDefault("integer","For claim or heartbeat: 15..900 seconds.",120),
  "task_id":prop("string","Task to complete, heartbeat or fail."),
  "evidence_sha256":prop("string","On completion: SHA-256 of independently retained evidence. No raw evidence or secrets."),
  "failure_code":propEnum("On failure: controlled reason.","timeout","tool_error","blocked","insufficient_evidence"),
 },"action")
}
var boardManagers=struct{
 sync.Mutex
 values map[string]*bunnyharness.Manager
}{values:map[string]*bunnyharness.Manager{}}
func boardManager()*bunnyharness.Manager{
 root:=filepath.Clean(config.Path("bunnymind","boards"))
 boardManagers.Lock()
 defer boardManagers.Unlock()
 if existing,ok:=boardManagers.values[root];ok{return existing}
 m:=bunnyharness.New(root)
 boardManagers.values[root]=m
 return m
}
func (investigationBoardTool) Execute(_ context.Context,in Input)Result{
 if strings.TrimSpace(in.SessionID)==""{return Errorf("investigation board requires a session")}
 var args struct{
  Action string `json:"action"`
  Tasks []bunnyharness.Task `json:"tasks"`
  MaxParallel int `json:"max_parallel"`
  LeaseSeconds int `json:"lease_seconds"`
  TaskID string `json:"task_id"`
  EvidenceSHA256 string `json:"evidence_sha256"`
  FailureCode string `json:"failure_code"`
 }
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid investigation board arguments: %v",err)}
 m:=boardManager()
 if args.LeaseSeconds==0{args.LeaseSeconds=120}
 if args.MaxParallel==0{args.MaxParallel=2}
 var response any
 var err error
 switch args.Action{
 case "plan":
  response,err=m.Init(in.SessionID,args.Tasks,args.MaxParallel)
 case "claim":
  response,err=m.ClaimNext(in.SessionID,in.SessionID,args.LeaseSeconds)
 case "heartbeat":
  err=m.Heartbeat(in.SessionID,in.SessionID,args.TaskID,args.LeaseSeconds)
  response=map[string]any{"task_id":args.TaskID,"lease_extended":err==nil}
 case "complete":
  err=m.Complete(in.SessionID,in.SessionID,args.TaskID,args.EvidenceSHA256)
  response=map[string]any{"task_id":args.TaskID,"completed":err==nil}
 case "fail":
  err=m.Fail(in.SessionID,in.SessionID,args.TaskID,args.FailureCode)
  response=map[string]any{"task_id":args.TaskID,"state_changed":err==nil}
 case "status":
  response,err=m.Status(in.SessionID)
 default:return Errorf("unknown investigation board action %q",args.Action)
 }
 if err!=nil{return Errorf("investigation board: %v",err)}
 b,err:=json.MarshalIndent(response,"","  ")
 if err!=nil{return Errorf("investigation board response: %v",err)}
 out:=Text(fmt.Sprintf("%s",b))
 // Record only real, successful board state transitions. The digest is
 // caller-provided evidence metadata, not an independently validated PoC.
 var event *bunnytimeline.Entry
 switch args.Action {
 case "plan":
  event=&bunnytimeline.Entry{Lane:"activity",Action:"map",State:"queued",Source:bunnytimeline.SourceTool}
 case "claim":
  if task,ok:=response.(bunnyharness.Task);ok{
   event=&bunnytimeline.Entry{Lane:"exploration",Action:"test",State:"running",
    Source:bunnytimeline.SourceTool,TaskID:task.ID}
  }
 case "complete":
  event=&bunnytimeline.Entry{Lane:"exploration",Action:"test",State:"succeeded",
   Source:bunnytimeline.SourceTool,TaskID:args.TaskID,EvidenceSHA256:args.EvidenceSHA256}
 case "fail":
  state:="failed";if args.FailureCode=="blocked"{state="blocked"}
  event=&bunnytimeline.Entry{Lane:"exploration",Action:"test",State:state,
   Source:bunnytimeline.SourceTool,TaskID:args.TaskID}
 }
 if event!=nil {
  if _,err:=timelineStore().Append(in.SessionID,*event);err!=nil{
   out.Meta=map[string]any{"timeline_warning":"board operation succeeded but telemetry persistence failed"}
  }
 }
 return out
}
