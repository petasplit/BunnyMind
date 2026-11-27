package bunnyscript

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "net/url"
 "regexp"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
)

const MaxCases=24
var validID=regexp.MustCompile(`^[a-zA-Z0-9_-]{1,48}$`)
var validPersona=regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
type Case struct{
 SampleID string `json:"sample_id"`
 Kind string `json:"kind"`
 Persona string `json:"persona,omitempty"`
 Method string `json:"method"`
 Path string `json:"path"`
}
type Plan struct{
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 Origin string `json:"origin"`
 Marker string `json:"marker"`
 MinIntervalMS int `json:"min_interval_ms"`
 Cases []Case `json:"cases"`
}
type EvidenceSummary struct{
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 ScriptFile string `json:"script_file"`
 ScriptSHA256 string `json:"script_sha256"`
 PlanSHA256 string `json:"plan_sha256"`
 RawEvidenceFile string `json:"raw_evidence_file"`
 RawEvidenceSHA256 string `json:"raw_evidence_sha256"`
 Cases int `json:"cases"`
 Candidates int `json:"candidates"`
 Controls int `json:"controls"`
 ConsistentCandidates int `json:"consistent_candidates"`
 ConsistentControls int `json:"consistent_controls"`
 Outcome string `json:"outcome"`
 Limitations string `json:"limitations"`
 Receipts []SampleReceipt `json:"receipts"`
}
type SampleReceipt struct{
 SampleID string `json:"sample_id"`
 Kind string `json:"kind"`
 Persona string `json:"persona,omitempty"`
 Status int `json:"status"`
 RequestSHA256 string `json:"request_sha256"`
 ResponseSHA256 string `json:"response_sha256"`
 MarkerPresent bool `json:"marker_present"`
 Truncated bool `json:"truncated"`
 ObservedAt string `json:"observed_at"`
}
func SHA(data []byte)string{
 h:=sha256.Sum256(data)
 return hex.EncodeToString(h[:])
}
func normalizedOrigin(raw string)(string,error){
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||u.Hostname()==""||
 u.RawQuery!=""||u.Fragment!=""||(u.Path!=""&&u.Path!="/"){return "",errors.New("exact HTTP(S) origin required")}
 switch u.Scheme{
 case "https":
  if u.Port()!=""&&u.Port()!="443"{return "",errors.New("approved HTTPS tests use port 443")}
  if strings.HasSuffix(u.Hostname(),"."){return "",errors.New("hostname must not have trailing dot")}
  if net.ParseIP(u.Hostname())!=nil{return "",errors.New("external test origins require an approved public DNS name")}
  return "https://"+strings.ToLower(u.Hostname()),nil
 case "http":
  ip:=net.ParseIP(u.Hostname())
  if ip==nil||!ip.IsLoopback()||u.Port()==""{
   return "",errors.New("HTTP is restricted to numeric loopback fixtures")}
  return "http://"+u.Host,nil
 default:return "",errors.New("unsupported scheme")
 }
}
func validPath(raw string)bool{
 if len(raw)<1||len(raw)>1024||!strings.HasPrefix(raw,"/")||
 strings.HasPrefix(raw,"//")||strings.ContainsAny(raw,"\\\r\n# ")||
 strings.Contains(raw,"%2f")||strings.Contains(raw,"%2F")||
 strings.Contains(raw,"%5c")||strings.Contains(raw,"%5C")||
 strings.Contains(raw,"%2e")||strings.Contains(raw,"%2E"){return false}
 u,err:=url.ParseRequestURI(raw)
 if err!=nil||u==nil||u.IsAbs()||u.Host!=""||u.Fragment!=""{return false}
 for _,seg:=range strings.Split(u.Path,"/"){
  if seg=="."||seg==".."{return false}
 }
 return true
}
func Validate(p Plan,policy bunnyguard.Policy)error{
 if !validID.MatchString(p.EngagementID)||p.EngagementID!=policy.EngagementID||
 !validID.MatchString(p.RunID){return errors.New("run and engagement identifiers must match approved manifest")}
 origin,err:=normalizedOrigin(p.Origin)
 if err!=nil{return err}
 approved:=false
 for _,raw:=range policy.AllowedOrigins{
  valid,e:=normalizedOrigin(raw)
  if e==nil&&valid==origin{approved=true}
 }
 if !approved{return errors.New("test origin not explicitly authorized")}
 if len(p.Cases)<4||len(p.Cases)>MaxCases||len(p.Cases)>policy.MaxNetworkCalls{
  return errors.New("proof run requires 4..24 cases within engagement request budget")
 }
 if len(p.Marker)<6||len(p.Marker)>120||strings.ContainsAny(p.Marker,"\r\n"){
  return errors.New("a unique harmless proof marker is required")
 }
 if p.MinIntervalMS<0||p.MinIntervalMS>5000||p.MinIntervalMS<policy.MinIntervalMS{
  return errors.New("request interval weakens the engagement's rate limit")
 }
 granted:=map[string]bool{}
 for _,m:=range policy.AllowedMethods{granted[strings.ToUpper(m)]=true}
 if len(granted)==0{granted["GET"]=true;granted["HEAD"]=true}
 candidates,controls:=0,0
 ids:=map[string]bool{}
 for _,c:=range p.Cases{
  if !validID.MatchString(c.SampleID)||ids[c.SampleID]||!validPath(c.Path){
   return fmt.Errorf("invalid or duplicate test case %q",c.SampleID)
  }
  ids[c.SampleID]=true
  if c.Persona!=""&&!validPersona.MatchString(c.Persona){return errors.New("invalid test persona")}
  if (c.Method!="GET"&&c.Method!="HEAD")||!granted[c.Method]{
   return errors.New("generated proof scripts only permit authorized GET/HEAD")
  }
  if c.Kind=="candidate"{candidates++}else if c.Kind=="control"{controls++}else{
   return errors.New("test kind must be candidate or control")
  }
 }
 if candidates<2||controls<2{return errors.New("require at least two candidate and two negative control requests")}
 return nil
}
func ValidateJSON(raw []byte,policy bunnyguard.Policy)(Plan,error){
 if len(raw)==0||len(raw)>32*1024{return Plan{},errors.New("plan must be 1..32 KiB")}
 decoder:=json.NewDecoder(strings.NewReader(string(raw)))
 decoder.DisallowUnknownFields()
 var p Plan
 if err:=decoder.Decode(&p);err!=nil{return Plan{},err}
 var rest any
 if err:=decoder.Decode(&rest);err==nil{return Plan{},errors.New("extra plan object forbidden")}
 if err:=Validate(p,policy);err!=nil{return Plan{},err}
 return p,nil
}
