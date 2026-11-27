package tools

import (
 "context"
 "encoding/json"
 "path/filepath"
 "strings"
 "sync"

 "github.com/enowdev/antares/internal/bunnygraph"
 "github.com/enowdev/antares/internal/config"
)

// inventoryGraphTool stores and compares caller-supplied asset snapshots.
// It cannot discover or independently authenticate network observations.
type inventoryGraphTool struct{}
func (inventoryGraphTool) Name()string{return "inventory_graph"}
func (inventoryGraphTool) Description()string{
 return "Record a bounded inventory snapshot and compare it to the last one "+
 "in this session. Outputs added/changed/removed asset IDs and graph edges. "+
 "No network calls. Source labels and fingerprints are supplied by the caller, not verified."
}
func (inventoryGraphTool) RequiresApproval()bool{return false}
func (inventoryGraphTool) Schema()map[string]any{
 return schema(map[string]any{
  "action":propEnum("Inventory action.","update","status"),
  "assets":map[string]any{
   "type":"array",
   "description":"For update: observed or inferred graph assets (do not include credentials, query strings or sensitive paths).",
   "items":map[string]any{"type":"object","properties":map[string]any{
    "id":prop("string","Stable asset ID."),
    "kind":propEnum("Asset kind.","origin","endpoint","service","technology","repository","dependency"),
    "key":prop("string","Non-sensitive origin, endpoint or component key."),
    "fingerprint_sha256":prop("string","SHA-256 of non-secret fingerprint data."),
    "source":propEnum("Origin of the observation.","captured_http","source_inventory","user_supplied","inferred"),
   },"required":[]string{"id","kind","key","fingerprint_sha256","source"}},
  },
  "links":map[string]any{
   "type":"array",
   "description":"Graph relationships between asset IDs.",
   "items":map[string]any{"type":"object","properties":map[string]any{
    "from":prop("string","Source asset ID."),
    "to":prop("string","Destination asset ID."),
    "relation":propEnum("Graph edge type.","contains","calls","depends_on","protected_by","resolves_to"),
   },"required":[]string{"from","to","relation"}},
  },
 },"action")
}
var inventoryManagers=struct{
 sync.Mutex
 entries map[string]*bunnygraph.Store
}{entries:map[string]*bunnygraph.Store{}}
func inventoryManager()*bunnygraph.Store{
 root:=filepath.Clean(config.Path("bunnymind","inventory"))
 inventoryManagers.Lock();defer inventoryManagers.Unlock()
 if s,ok:=inventoryManagers.entries[root];ok{return s}
 s:=bunnygraph.New(root)
 inventoryManagers.entries[root]=s
 return s
}
func (inventoryGraphTool) Execute(_ context.Context,in Input)Result{
 if strings.TrimSpace(in.SessionID)==""{return Errorf("inventory graph needs a session")}
 var args struct{
  Action string `json:"action"`
  Assets []bunnygraph.Asset `json:"assets"`
  Links []bunnygraph.Link `json:"links"`
 }
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid inventory input: %v",err)}
 m:=inventoryManager()
 var out any
 var err error
 switch args.Action{
 case "update":
  out,err=m.Update(in.SessionID,bunnygraph.Snapshot{Assets:args.Assets,Links:args.Links})
 case "status":
  out,err=m.Summary(in.SessionID)
 default:return Errorf("invalid inventory action %q",args.Action)
 }
 if err!=nil{return Errorf("inventory operation failed: %v",err)}
 payload,err:=json.MarshalIndent(out,"","  ")
 if err!=nil{return Errorf("inventory serialization failed: %v",err)}
 return Text(string(payload))
}
