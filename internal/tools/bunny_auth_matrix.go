package tools

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnymatrix"
 "github.com/enowdev/antares/internal/bunnytimeline"
)

// authAccessMatrixTool compares structured, operator-approved test-account
// observations offline. The model cannot use it to make network requests.
type authAccessMatrixTool struct{}
func (authAccessMatrixTool) Name() string {return "auth_access_matrix"}
func (authAccessMatrixTool) Description() string {
 return "Offline differential authorization review of owner, peer and anonymous "+
  "test-account observations from an explicitly authorized engagement. "+
  "Requires a benign pre-seeded owner-resource marker, HTTP status and "+
  "sanitized evidence digest; detects candidate cross-identity access while "+
  "distinguishing denied, missing baseline and inconclusive controls. "+
  "No requests, account creation, cookies, raw URLs or verified exploit claims."
}
func (authAccessMatrixTool) RequiresApproval() bool{return false}
func (authAccessMatrixTool) Schema()map[string]any{
 return schema(map[string]any{
  "observations":map[string]any{
   "type":"array",
   "description":"Up to 256 sanitized records, from approved test personas, without raw tokens/URL/PII.",
   "items":map[string]any{"type":"object","properties":map[string]any{
    "id":prop("string","Unique safe observation identifier."),
    "case_id":prop("string","Stable case group."),
    "endpoint_id":prop("string","Safe/opaque endpoint identifier."),
    "resource_sha256":prop("string","Digest identifying the same seeded test resource across actors."),
    "owner_id":prop("string","Safe owner test-persona identifier."),
    "actor_id":prop("string","Owner, peer, or 'anonymous'."),
    "method":propEnum("Observed method.","GET","HEAD","POST"),
    "status":prop("integer","Observed HTTP status, 100..599."),
    "marker_signal":propEnum("Whether the predefined harmless resource marker was present.","present","absent","unknown"),
    "marker_sha256":prop("string","SHA-256 of harmless marker, required only when present."),
    "evidence_sha256":prop("string","Digest of separately retained sanitized observation."),
    "source":propEnum("Caller-declared provenance (not attested).","operator_supplied","captured_har","synthetic_fixture"),
   },"required":[]string{"id","case_id","endpoint_id","resource_sha256","owner_id","actor_id","method","status","marker_signal","evidence_sha256","source"}},
  },
 },"observations")
}
func (authAccessMatrixTool) UntrustedOutput()bool{return true}
func (authAccessMatrixTool) Execute(_ context.Context,in Input)Result{
 if strings.TrimSpace(in.SessionID)==""{return Errorf("access matrix requires a session")}
 path:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if path==""{return Errorf("access matrix requires an existing BunnyGuard engagement")}
 if _,err:=bunnyguard.New(path);err!=nil{return Errorf("invalid authorization manifest")}
 if len(in.Args)==0||len(in.Args)>131072{return Errorf("access matrix argument size exceeds budget")}
 var args struct {Observations []bunnymatrix.Observation `json:"observations"`}
 dec:=json.NewDecoder(bytes.NewReader(in.Args));dec.DisallowUnknownFields()
 if err:=dec.Decode(&args);err!=nil{return Errorf("invalid matrix input: %v",err)}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return Errorf("matrix input must be one JSON object")}
 report,err:=bunnymatrix.Analyze(args.Observations)
 if err!=nil{return Errorf("access matrix rejected: %v",err)}
 body,err:=json.MarshalIndent(report,"","  ")
 if err!=nil{return Errorf("could not encode access matrix")}
 out:=Text(string(body))
 digest:=sha256.Sum256(body)
 state:="succeeded"
 if report.Outcomes["cross_identity_candidate"]>0||
  report.Outcomes["repeated_cross_identity_candidate"]>0||
  report.Outcomes["anonymous_resource_access_candidate"]>0 {
  state="needs_review"
 }
 _,err=timelineStore().Append(in.SessionID,bunnytimeline.Entry{
  Lane:"evidence",Action:"map",State:state,Source:bunnytimeline.SourceTool,
  AssetID:"matrix_"+hex.EncodeToString(digest[:8]),EvidenceSHA256:hex.EncodeToString(digest[:]),
 })
 if err!=nil{out.Meta=map[string]any{"timeline_warning":"offline analysis succeeded, but telemetry persistence failed"}}
 return out
}
