package tools

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnytimeline"
)

// approvedAdaptiveAuthTool executes only locally preconfigured, explicitly
// authorized login/signup discovery and dedicated mailbox verification.
// It accepts no model-provided target URL, account name, email, or password.
type approvedAdaptiveAuthTool struct{}
func (approvedAdaptiveAuthTool) Name()string{return "approved_adaptive_auth"}
func (approvedAdaptiveAuthTool) Description()string{
 return "Discover unfamiliar authentication fields on approved external HTTPS "+
 "applications and execute a bounded sign-in or signup workflow for preapproved "+
 "test personas. Reads account secrets from the OS credential store and "+
 "optionally retrieves time-correlated email verification codes from trusted "+
 "dedicated IMAP test mailboxes. All targets and actors come from operator-owned "+
 "scope/config files. Does not accept model arguments, bypass MFA/anti-bot "+
 "controls, mutate arbitrary parameters, or exceed declared POST endpoints."
}
func (approvedAdaptiveAuthTool) Schema()map[string]any{return schema(map[string]any{})}
func (approvedAdaptiveAuthTool) RequiresApproval()bool{return false}
func (approvedAdaptiveAuthTool) Execute(ctx context.Context,in Input)Result{
 if len(in.Args)>0&&strings.TrimSpace(string(in.Args))!="{}"{
  return Errorf("adaptive auth accepts no model-supplied target, persona or credentials")
 }
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 scopePath:=strings.TrimSpace(os.Getenv(scopeEnv))
 adaptivePath:=strings.TrimSpace(os.Getenv("BUNNY_APPROVED_ADAPTIVE_CONFIG"))
 if policyPath==""||scopePath==""||adaptivePath==""{
  return Errorf("operator-owned BunnyGuard, browser scope and adaptive config files are required")
 }
 guard,err:=bunnyguard.New(policyPath)
 if err!=nil{return Errorf("invalid engagement manifest")}
 scope,err:=bunnybrowserflow.LoadApprovedScope(scopePath,policyPath)
 if err!=nil{return Errorf("invalid approved browser scope: %v",err)}
 batch,err:=bunnybrowserflow.LoadAdaptiveBatch(adaptivePath)
 if err!=nil{return Errorf("invalid operator-defined test identities or auth mode")}
 var secrets bunnybrowserflow.Secrets=bunnybrowserflow.KeyringSecrets{}
 if mailboxPath:=strings.TrimSpace(os.Getenv("BUNNY_APPROVED_MAILBOX_CONFIG"));mailboxPath!=""{
  mailbox,err:=bunnybrowserflow.LoadMailboxConfiguration(mailboxPath)
  if err!=nil{return Errorf("invalid dedicated test mailbox configuration")}
  secrets,err=bunnybrowserflow.NewTrustedMailboxSecrets(
   mailbox,bunnybrowserflow.IMAPTransport{},bunnybrowserflow.KeyringSecrets{})
  if err!=nil{return Errorf("trusted mailbox setup rejected")}
 }
 output,err:=bunnybrowserflow.RunConfiguredAdaptive(ctx,scope,batch,secrets,
  trustedHandoff{ask:in.AskUser},guard.Manifest(),false)
 if err!=nil{return Errorf("authorized adaptive browser flow did not complete: %v",err)}
 data,err:=json.MarshalIndent(output,"","  ")
 if err!=nil{return Errorf("adaptive result encoding failed")}
 result:=Text(string(data))
 if in.SessionID!=""{
  digest:=sha256.Sum256(data)
  _,err=timelineStore().Append(in.SessionID,bunnytimeline.Entry{
   Lane:"auth",Action:"sign_in",State:"succeeded",Source:bunnytimeline.SourceTool,
   AssetID:"adaptive_"+hex.EncodeToString(digest[:8]),
   EvidenceSHA256:hex.EncodeToString(digest[:]),
  })
  if err!=nil{result.Meta=map[string]any{"timeline_warning":"adaptive auth completed but evidence journal failed"}}
 }
 return result
}
