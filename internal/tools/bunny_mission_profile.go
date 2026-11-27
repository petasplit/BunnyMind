package tools

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "io"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnymission"
)
const missionEnv="BUNNY_MISSION_PROFILE"
type missionProfileTool struct{}
func (missionProfileTool) Name()string{return "engagement_profile"}
func (missionProfileTool) Description()string{
 return "Read the operator's local Dorkix-style Normal/Full assessment profile, "+
 "with ranked additional targets, an explicit time budget and bounded per-target "+
 "request allowances, intersected against the current BunnyGuard authorization "+
 "manifest. This tool produces a reviewable mission schedule without network "+
 "traffic, shell commands or model-selected target expansion."
}
func (missionProfileTool) RequiresApproval()bool{return false}
func (missionProfileTool) Schema()map[string]any{return schema(map[string]any{})}
func (missionProfileTool) Execute(_ context.Context,in Input)Result{
 if len(in.Args)>0&&string(in.Args)!="{}"{return Errorf("mission profile accepts no target arguments")}
 guardPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 path:=strings.TrimSpace(os.Getenv(missionEnv))
 if guardPath==""||path==""{return Errorf("operator-owned BunnyGuard and mission profile are required")}
 guard,err:=bunnyguard.New(guardPath)
 if err!=nil{return Errorf("invalid BunnyGuard policy")}
 f,err:=os.Open(path)
 if err!=nil{return Errorf("mission profile file unavailable")}
 defer f.Close()
 raw,err:=io.ReadAll(io.LimitReader(f,32769))
 if err!=nil||len(raw)>32768{return Errorf("mission profile exceeds 32 KiB")}
 var p bunnymission.Profile
 decoder:=json.NewDecoder(bytes.NewReader(raw))
 decoder.DisallowUnknownFields()
 if err:=decoder.Decode(&p);err!=nil{return Errorf("invalid mission profile JSON")}
 var extra any
 if err:=decoder.Decode(&extra);!errors.Is(err,io.EOF){return Errorf("mission profile must contain a single JSON object")}
 summary,err:=bunnymission.Build(p,guard.Manifest())
 if err!=nil{return Errorf("mission profile rejected: %v",err)}
 b,err:=json.MarshalIndent(summary,"","  ")
 if err!=nil{return Errorf("mission profile serialization failed")}
 return Text(string(b))
}
