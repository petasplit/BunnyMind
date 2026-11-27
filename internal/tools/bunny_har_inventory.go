package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/enowdev/antares/internal/bunnyguard"
	"github.com/enowdev/antares/internal/bunnyhar"
	"github.com/enowdev/antares/internal/bunnytimeline"
)

// harContextInventoryTool consumes an operator-supplied HAR file only inside
// the active workspace and only with an existing BunnyGuard scope manifest.
// It does not replay requests or return credentials, tokens, or raw URLs.
type harContextInventoryTool struct{}
func (harContextInventoryTool) Name() string { return "har_context_inventory" }
func (harContextInventoryTool) Description() string {
	return "Analyze one operator-supplied .har JSON file in the session workspace "+
		"using BunnyGuard-approved origins, without sending network requests. "+
		"Returns hashed endpoint IDs, in-scope coverage and auth-presence counters; "+
		"no headers, tokens, query strings, bodies, or raw paths leave the importer. "+
		"An imported HAR is not proof of a current vulnerability."
}
func (harContextInventoryTool) RequiresApproval() bool { return false }
func (harContextInventoryTool) UntrustedOutput() bool { return true }
func (harContextInventoryTool) Schema() map[string]any {
	return schema(map[string]any{
		"path":prop("string","Relative filename of a locally supplied HAR inside this workspace."),
	},"path")
}

func (harContextInventoryTool) Execute(_ context.Context,in Input) Result {
	if strings.TrimSpace(in.SessionID)=="" {return Errorf("HAR import requires an active session")}
	if strings.TrimSpace(in.Workspace)=="" {return Errorf("HAR import requires a workspace")}
	var args struct {Path string `json:"path"`}
	if len(in.Args)==0||len(in.Args)>2048{return Errorf("HAR import arguments are missing or too large")}
	d:=json.NewDecoder(bytes.NewReader(in.Args));d.DisallowUnknownFields()
	if err:=d.Decode(&args);err!=nil{return Errorf("invalid HAR import arguments: %v",err)}
	var extra any
	if err:=d.Decode(&extra);err!=io.EOF{return Errorf("HAR import expects one JSON object")}
	if filepath.IsAbs(args.Path)||strings.TrimSpace(args.Path)==""||
	   !strings.EqualFold(filepath.Ext(args.Path),".har"){
		return Errorf("HAR must be a relative .har file inside the workspace")
	}
	base,err:=filepath.EvalSymlinks(in.Workspace)
	if err!=nil{return Errorf("workspace unavailable")}
	candidate,err:=filepath.EvalSymlinks(filepath.Join(base,args.Path))
	if err!=nil{return Errorf("HAR file unavailable")}
	rel,err:=filepath.Rel(base,candidate)
	if err!=nil||rel==".."||strings.HasPrefix(rel,".."+string(os.PathSeparator))||filepath.IsAbs(rel){
		return Errorf("HAR must remain inside the workspace; symlink escapes are prohibited")
	}
	path:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
	if path==""{return Errorf("HAR analysis requires an explicit BunnyGuard policy")}
	g,err:=bunnyguard.New(path)
	if err!=nil{return Errorf("invalid engagement policy")}
	f,err:=os.Open(candidate)
	if err!=nil{return Errorf("HAR file unavailable")}
	defer f.Close()
	stat,err:=f.Stat()
	if err!=nil||!stat.Mode().IsRegular()||stat.Size()>bunnyhar.MaxFileBytes{
		return Errorf("HAR file must be regular and at most 8 MiB")
	}
	report,err:=bunnyhar.Analyze(f,g.Manifest().AllowedOrigins)
	if err!=nil{return Errorf("HAR analysis rejected: %v",err)}
	body,err:=json.MarshalIndent(report,"","  ")
	if err!=nil{return Errorf("HAR inventory encoding failed")}
	out:=Text(string(body))
	// This is a tool-observed local file analysis, not a live HTTP scan.
	sum:=sha256.Sum256(body)
	_,err=timelineStore().Append(in.SessionID,bunnytimeline.Entry{
		Lane:"exploration",Action:"map",State:"succeeded",
		Source:bunnytimeline.SourceTool,
		AssetID:"har_"+hex.EncodeToString(sum[:8]),
		EvidenceSHA256:hex.EncodeToString(sum[:]),
	})
	if err!=nil{out.Meta=map[string]any{"timeline_warning":"HAR parsed but telemetry persistence failed"}}
	return out
}
