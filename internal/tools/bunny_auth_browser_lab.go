package tools

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnytimeline"
)

// authBrowserLabTool runs a full browser-based registration/OTP/identity test
// only against its own disposable numeric-loopback server.
type authBrowserLabTool struct{}
func (authBrowserLabTool) Name()string{return "auth_browser_lab"}
func (authBrowserLabTool) Description()string{
 return "Run a disposable two-persona real-Chromium signup and trusted local "+
 "verification-code workflow. Each persona gets its own browser profile and "+
 "session cookie. All page requests are intercepted and restricted to the "+
 "tool-created numeric-loopback origin. Does not accept a target URL, external "+
 "email or credentials and never bypasses human MFA or anti-bot challenges."
}
func (authBrowserLabTool) RequiresApproval()bool{return false}
func (authBrowserLabTool) Schema()map[string]any{return schema(map[string]any{})}
func (authBrowserLabTool) Execute(ctx context.Context,in Input)Result {
 if len(in.Args)>0&&string(in.Args)!="{}"{return Errorf("local browser lab accepts no external URL, credentials or options")}
 output,err:=bunnybrowserflow.RunLab(ctx)
 if err!=nil{return Errorf("isolated browser workflow unavailable or failed: %v",err)}
 data,err:=json.MarshalIndent(output,"","  ")
 if err!=nil{return Errorf("local browser result unavailable")}
 result:=Text(string(data))
 if in.SessionID!=""{
  hash:=sha256.Sum256(data)
  _,err=timelineStore().Append(in.SessionID,bunnytimeline.Entry{
   Lane:"auth",Action:"sign_in",State:"succeeded",
   Source:bunnytimeline.SourceTool,
   AssetID:"lab_"+hex.EncodeToString(hash[:8]),
   EvidenceSHA256:hex.EncodeToString(hash[:]),
  })
  if err!=nil{result.Meta=map[string]any{"timeline_warning":"browser demo passed, but timeline journal failed"}}
 }
 return result
}
