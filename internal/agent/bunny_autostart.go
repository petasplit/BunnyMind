package agent

import (
 "net/url"
 "os"
 "regexp"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/llm"
)

var securityURLPattern=regexp.MustCompile("https?://[^\\s<>\\\"']+")
func authorizedSecurityURL(message string,origins []string)bool{
 if len(origins)==0{return false}
 allowed:=map[string]bool{}
 for _,raw:=range origins{
  u,err:=url.Parse(raw)
  if err==nil&&u!=nil&&u.User==nil&&(u.Scheme=="http"||u.Scheme=="https")&&u.Host!=""{
   allowed[strings.ToLower(u.Scheme+"://"+u.Host)]=true
  }
 }
 for _,match:=range securityURLPattern.FindAllString(message,24){
  value:=strings.TrimRight(match,".,;)]}!")
  u,err:=url.Parse(value)
  if err!=nil||u==nil||u.User!=nil||u.Host==""||u.Opaque!=""{continue}
  if allowed[strings.ToLower(u.Scheme+"://"+u.Host)]{return true}
 }
 return false
}
func securityAssessmentRequest(req Request)bool{
 r:=strings.ToLower(strings.TrimSpace(req.Role))
 if r=="security"||strings.HasPrefix(r,"security-"){return true}
 if r!=""||strings.TrimSpace(req.Toolset)!=""{return false}
 m:=strings.ToLower(req.Message)
 scope:=strings.Contains(m,"scope")||strings.Contains(m,"authorized")||strings.Contains(m,"authorised")
 security:=strings.Contains(m,"pentest")||strings.Contains(m,"bug bounty")||
  strings.Contains(m,"security assessment")||strings.Contains(m,"vulnerability")||
  strings.Contains(m,"reconnaissance")
 return scope&&security
}
// readySecurityMission requires a valid BunnyGuard policy AND an in-scope URL
// supplied by the user. Merely saying "authorized" never authorizes traffic.
func readySecurityMission(req Request)bool{
 if req.Quiet||req.Depth!=0||!securityAssessmentRequest(req){return false}
 path:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if path==""{return false}
 guard,err:=bunnyguard.New(path)
 if err!=nil{return false}
 return authorizedSecurityURL(req.Message,guard.Manifest().AllowedOrigins)
}
func autoSelectSecurityRole(req *Request){
 if req==nil||req.Role!=""||req.Toolset!=""{return}
 if readySecurityMission(*req){req.Role="security"}
}
func toolAvailable(specs []llm.Tool,name string)bool{
 for _,tool:=range specs{if tool.Name==name{return true}}
 return false
}
// Tool-first mode requires an actually available approved reader. If the
// toolset lacks it, we cannot silently substitute an unrestricted network
// tool just to make the engagement appear autonomous.
func toolFirstMission(req Request,specs []llm.Tool)bool{
 return readySecurityMission(req)&&toolAvailable(specs,"scoped_read")
}
const securityToolFirstInstructions=`
## BunnyMind security engagement: direct execution

The user has already supplied the target, scope and assessment instructions.
The runtime checked a BunnyGuard manifest and an exact allowed URL origin.
Do NOT repeat the brief, announce a plan, introduce yourself, or describe
what you intend to do. FIRST call an actual tool with no prose: prefer
scoped_read on the in-scope URL using a non-mutating GET. Then investigate
observed application behavior and preserve a concise evidence trail.

The UI shows action statuses derived from actual tool execution. Never
claim to be crawling, signing in, or proving a vulnerability unless the
corresponding operation really ran. Honor the engagement's allowed origins,
HTTP methods, request budget and pacing. Do not use legacy HTTP tools,
browsers, shells, subprocesses, or plugins to bypass engagement restrictions.

The current auth_workflow_lab signs up only disposable synthetic localhost
accounts. It does NOT create accounts on the target application; do not
treat that lab tool as a target login. Use real target credentials only if
a separately operator-approved, scope-bound adapter has been configured.
For MFA, CAPTCHA, or anti-abuse challenges, request authorized human action.

Report only observed results and genuine blockers. A model's claim is not
evidence and intermediary blocks are not proof of application security.
`
func firstSecurityToolChoice(enabled bool)string{
 if enabled{return "required"}
 return ""
}
func securityActionStatus(name string)string{
 switch name{
 case "scoped_read":return "Inspecting in-scope URL"
 case "inventory_graph":return "Mapping observed assets"
 case "investigation_board":return "Updating investigation tasks"
 case "engagement_blackboard":return "Reviewing engagement observations"
 case "review_evidence","verify_lab_receipts","assess_authz_receipts","compare_authz_fix_receipts","compare_build_bound_fix":
  return "Checking evidence"
 case "auth_workflow_lab":return "Testing synthetic sign-in"
 case "research_next_step":return "Evaluating test signals"
 case "exploration_timeline":return "Recording exploration history"
 case "har_context_inventory":return "Inspecting captured request metadata"
 case "auth_access_matrix":return "Comparing test-account access evidence"
 case "auth_browser_lab":return "Testing isolated browser sign-in"
 case "approved_browser_auth":return "Running approved external sign-in workflow"
 case "finding_focus":return "Reviewing recorded finding evidence"
 case "engagement_profile":return "Prioritizing approved assessment targets"
 case "python_proof_run":return "Generating and validating Python HTTP evidence"
 case "list_roles":return "Selecting specialists"
 case "delegate_task":return "Starting specialist inspection"
 case "report_finding","triage_finding":return "Recording finding evidence"
 case "methodology_status":return "Checking assessment coverage"
 default:return ""
 }
}
