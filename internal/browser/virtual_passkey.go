package browser

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
)

// setupVirtualPasskey enables a Chromium WebAuthn *test* authenticator.
// It is ephemeral and does not impersonate or bypass a physical security key.
// A credential is created by the normal application registration process,
// and disappears with this temporary browser session.
func (s *Session) setupVirtualPasskey(ctx context.Context,c *conn,sessionID string)error{
 if !s.opts.VirtualPasskey{return nil}
 if sessionID==""||c==nil{return errors.New("WebAuthn test requires active browser session")}
 if s.opts.ExternalProxyURL==""&&s.opts.LoopbackOrigin==""{
  return errors.New("virtual authenticator requires a scoped test browser")
 }
 if _,err:=c.send(ctx,sessionID,"WebAuthn.enable",map[string]any{"enableUI":false});err!=nil{
  return fmt.Errorf("WebAuthn test emulation unavailable: %w",err)
 }
 raw,err:=c.send(ctx,sessionID,"WebAuthn.addVirtualAuthenticator",map[string]any{
  "options":map[string]any{
   "protocol":"ctap2","transport":"internal",
   "hasResidentKey":true,"hasUserVerification":true,
   "automaticPresenceSimulation":true,"isUserVerified":true,
  },
 })
 if err!=nil{return fmt.Errorf("could not create WebAuthn test authenticator: %w",err)}
 var created struct{AuthenticatorID string `json:"authenticatorId"`}
 if json.Unmarshal(raw,&created)!=nil||created.AuthenticatorID==""{
  return errors.New("virtual authenticator returned no identifier")
 }
 return nil
}
