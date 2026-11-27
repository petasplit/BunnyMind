package bunnybrowserflow

import (
 "context"
 "errors"
 "regexp"
)

// A discovered control is only a stable synthetic selector and a semantic
// category. No DOM input value, label text, page body, cookie or credential is
// returned to the planner or agent.
type DiscoveredField struct {
 Selector string `json:"selector"`
 Role string `json:"role"`
}
type AuthPageState struct {
 Kind string `json:"kind"`
 Fields []DiscoveredField `json:"fields"`
 SubmitSelector string `json:"submit_selector,omitempty"`
 SignupPath string `json:"signup_path,omitempty"`
 Ambiguous bool `json:"ambiguous"`
 Challenge string `json:"challenge,omitempty"`
}
type DiscoveryBrowser interface {
 Browser
 DiscoverAuth(context.Context)(AuthPageState,error)
}
var safeDiscoverySelector=regexp.MustCompile(`^#bm-auto-[a-z]+-[0-9]{1,3}$`)
// Discovery deliberately accepts no arbitrary selectors from model output.
func validateDiscovery(d AuthPageState)error {
 if len(d.Fields)>8{return errors.New("too many authentication controls")}
 if d.SignupPath!=""&&!safePath(d.SignupPath){return errors.New("invalid signup link path")}
 if d.SubmitSelector!=""&&!safeDiscoverySelector.MatchString(d.SubmitSelector){return errors.New("invalid discovered submit ref")}
 seen:=map[string]bool{}
 roles:=map[string]bool{"email":true,"username":true,"password":true,"password_confirm":true,"otp":true}
 for _,f:=range d.Fields{
  if !roles[f.Role]||!safeDiscoverySelector.MatchString(f.Selector)||seen[f.Selector]{
   return errors.New("invalid or duplicate discovered authentication field")
  }
  seen[f.Selector]=true
 }
 switch d.Kind{case "login","signup","verification","challenge","unknown":default:return errors.New("unknown form type")}
 switch d.Challenge{case "","mfa","anti_bot","passkey":default:return errors.New("invalid challenge type")}
 return nil
}
