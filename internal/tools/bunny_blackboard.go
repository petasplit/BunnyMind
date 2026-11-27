package tools

import (
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "sync"

 "github.com/enowdev/antares/internal/bunnyblackboard"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/config"
)

// engagementBlackboardTool shares evidence references across Antares sessions
// only when they use the same explicit BunnyGuard engagement manifest.
type engagementBlackboardTool struct{}
func (engagementBlackboardTool) Name()string{return "engagement_blackboard"}
func (engagementBlackboardTool) Description()string{
 return "Read or submit bounded shared observations for the current authorized engagement. "+
 "An independent agent session can request reproduction or reject a record, but cannot mark it verified. "+
 "Evidence hashes and source labels are caller-provided, not authenticated. No network or shell activity."
}
func (engagementBlackboardTool) RequiresApproval()bool{return false}
func (engagementBlackboardTool) UntrustedOutput()bool{return true}
func (engagementBlackboardTool) Schema()map[string]any{
 return schema(map[string]any{
  "action":propEnum("Operation.","record","review","list","status"),
  "id":prop("string","Stable observation ID, 1..64 safe characters."),
  "kind":propEnum("Record category.","asset","observation","hypothesis","task_hint","retest"),
  "asset_id":prop("string","Optional stable asset ID, not a URL."),
  "label":prop("string","Short non-secret observation description; no credentials or PII."),
  "source":propEnum("Source category; not an attestation.","captured_http","source_inventory","operator","model_inference"),
  "evidence_sha256":prop("string","Lowercase SHA-256 of separately retained, sanitized evidence."),
  "verdict":propEnum("Review decision. Never means verified.","needs_reproduction","rejected"),
  "reason":propEnum("Controlled review rationale.","crosscheck","duplicate","stale","missing_evidence"),
  "limit":propDefault("integer","For list: maximum 1..50 returned records.",20),
 },"action")
}
var blackboardManagers=struct{
 sync.Mutex
 byRoot map[string]*bunnyblackboard.Store
}{byRoot:map[string]*bunnyblackboard.Store{}}
func blackboardManager()*bunnyblackboard.Store{
 root:=filepath.Clean(config.Path("bunnymind","blackboard"))
 blackboardManagers.Lock();defer blackboardManagers.Unlock()
 if s,ok:=blackboardManagers.byRoot[root];ok{return s}
 s:=bunnyblackboard.New(root)
 blackboardManagers.byRoot[root]=s
 return s
}
func (engagementBlackboardTool) Execute(_ context.Context,in Input)Result{
 if strings.TrimSpace(in.SessionID)==""{return Errorf("engagement blackboard requires a session")}
 path:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if path==""{return Errorf("engagement blackboard requires a BunnyGuard manifest")}
 policy,err:=bunnyguard.New(path)
 if err!=nil{return Errorf("invalid engagement manifest: %v",err)}
 engagement:=policy.Manifest().EngagementID
 var args struct{
  Action string `json:"action"`
  ID string `json:"id"`
  Kind string `json:"kind"`
  AssetID string `json:"asset_id"`
  Label string `json:"label"`
  Source string `json:"source"`
  EvidenceSHA256 string `json:"evidence_sha256"`
  Verdict string `json:"verdict"`
  Reason string `json:"reason"`
  Limit int `json:"limit"`
 }
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid blackboard arguments: %v",err)}
 store:=blackboardManager()
 var result any
 switch args.Action{
 case "record":
  record,added,err:=store.RecordSubmission(engagement,in.SessionID,bunnyblackboard.Submission{
   ID:args.ID,Kind:args.Kind,AssetID:args.AssetID,Label:args.Label,
   Source:args.Source,EvidenceHash:args.EvidenceSHA256,
  })
  if err!=nil{return Errorf("blackboard record rejected: %v",err)}
  result=map[string]any{"record":record,"added":added}
 case "review":
  record,err:=store.Review(engagement,in.SessionID,args.ID,args.Verdict,args.Reason)
  if err!=nil{return Errorf("blackboard review rejected: %v",err)}
  result=record
 case "status":
  summary,err:=store.Summary(engagement,0)
  if err!=nil{return Errorf("blackboard status failed: %v",err)}
  result=summary
 case "list":
  if args.Limit==0{args.Limit=20}
  summary,err:=store.Summary(engagement,args.Limit)
  if err!=nil{return Errorf("blackboard list failed: %v",err)}
  result=summary
 default:return Errorf("unsupported blackboard action %q",args.Action)
 }
 b,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return Errorf("blackboard output encoding failed: %v",err)}
 return Text(string(b))
}
