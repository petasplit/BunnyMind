// Package bunnyguard restricts model-selected tool calls for an engagement.
// It is an opt-in preflight, NOT an operating-system or network firewall.
package bunnyguard

import (
 "bufio"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net/url"
 "net"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "time"
)

const EnvPolicy = "ANTARES_BUNNY_GUARD_POLICY"

type Policy struct {
 EngagementID string `json:"engagement_id"`
 AllowedOrigins []string `json:"allowed_origins"`
 AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
 AllowedMethods []string `json:"allowed_methods,omitempty"`
 MaxNetworkCalls int `json:"max_network_calls"`
 MinIntervalMS int `json:"min_interval_ms,omitempty"`
 AuditPath string `json:"audit_path,omitempty"`
}
type Decision struct { Allowed bool; Reason string }
type Event struct {
 Seq int `json:"seq"`
 Time string `json:"time"`
 Engagement string `json:"engagement"`
 Session string `json:"session"`
 Tool string `json:"tool"`
 Origin string `json:"origin,omitempty"`
 Network bool `json:"network"`
 Allowed bool `json:"allowed"`
 Reason string `json:"reason"`
 ArgsHash string `json:"args_hash"`
 PrevHash string `json:"prev_hash"`
 Hash string `json:"hash"`
}
type Guard struct {
 mu sync.Mutex
 policy Policy
 origins map[string]bool
 methods map[string]bool
 auditPath string
 total, seq int
 last time.Time
 prevHash string
}
func digest(b []byte) string { h:=sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func eventHash(e Event) string { e.Hash=""; b,_:=json.Marshal(e); return digest(b) }
func parsedOrigin(s string, strictlyOrigin bool) (string,error) {
 u,err:=url.Parse(strings.TrimSpace(s))
 if err!=nil || u==nil || (u.Scheme!="http" && u.Scheme!="https") ||
 u.User!=nil || u.Hostname()=="" || u.Opaque!="" {
  return "",errors.New("absolute HTTP(S) URL without userinfo required")
 }
 if strictlyOrigin && ((u.Path!="" && u.Path!="/") || u.RawQuery!="" || u.Fragment!="") {
  return "",errors.New("origin must not include path/query/fragment")
 }
 return strings.ToLower(u.Scheme+"://"+u.Host),nil
}
// New loads a manifest and verifies prior audit events, including spent budget.
// Use one process per engagement; this does not implement cross-process locks.
func New(path string) (*Guard,error) {
 b,err:=os.ReadFile(path); if err!=nil{return nil,err}
 var p Policy
 d:=json.NewDecoder(strings.NewReader(string(b))); d.DisallowUnknownFields()
 if err:=d.Decode(&p);err!=nil{return nil,err}
 if strings.TrimSpace(p.EngagementID)=="" || len(p.AllowedOrigins)==0{return nil,errors.New("engagement_id and allowed_origins required")}
 if p.MaxNetworkCalls<1 || p.MaxNetworkCalls>100000 {return nil,errors.New("invalid request budget")}
 if p.MinIntervalMS<0 || p.MinIntervalMS>3600000 {return nil,errors.New("invalid minimum interval")}
 if len(p.AllowedCIDRs)>16{return nil,errors.New("too many CIDR exceptions")}
 for _,cidr:=range p.AllowedCIDRs{
  _,block,err:=net.ParseCIDR(cidr)
  if err!=nil{return nil,fmt.Errorf("invalid network exception %q",cidr)}
  bits,_:=block.Mask.Size();if bits==0{return nil,errors.New("default-route exception forbidden")}
 }
 g:=&Guard{policy:p,origins:map[string]bool{},methods:map[string]bool{}}
 for _,v:=range p.AllowedOrigins {
  o,err:=parsedOrigin(v,true);if err!=nil{return nil,fmt.Errorf("origin %s: %w",v,err)}
  g.origins[o]=true
 }
 if len(p.AllowedMethods)==0{p.AllowedMethods=[]string{"GET","HEAD","OPTIONS"}}
 for _,v:=range p.AllowedMethods{
  m:=strings.ToUpper(strings.TrimSpace(v))
  switch m {case "GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE":g.methods[m]=true
  default:return nil,fmt.Errorf("invalid method %s",v)}
 }
 g.policy=p
 g.auditPath=p.AuditPath
 if g.auditPath==""{g.auditPath="bunnyguard-audit.jsonl"}
 if !filepath.IsAbs(g.auditPath){g.auditPath=filepath.Join(filepath.Dir(path),g.auditPath)}
 if err:=g.verify();err!=nil{return nil,err}
 return g,nil
}
func (g *Guard) verify() error {
 f,err:=os.Open(g.auditPath);if os.IsNotExist(err){return nil};if err!=nil{return err}
 defer f.Close()
 s:=bufio.NewScanner(f);s.Buffer(make([]byte,64*1024),2*1024*1024)
 for s.Scan(){
  var e Event
  if err:=json.Unmarshal(s.Bytes(),&e);err!=nil{return err}
  if e.Seq!=g.seq+1||e.PrevHash!=g.prevHash||e.Hash!=eventHash(e)||e.Engagement!=g.policy.EngagementID{
   return fmt.Errorf("invalid audit chain at event %d",g.seq+1)
  }
  g.seq,g.prevHash=e.Seq,e.Hash
  if e.Network&&e.Allowed{
   g.total++
   if t,err:=time.Parse(time.RFC3339Nano,e.Time);err==nil{g.last=t}
  }
 }
 return s.Err()
}
func (g *Guard) appendAudit(session,tool,args,origin string,network bool,d Decision)error{
 if err:=os.MkdirAll(filepath.Dir(g.auditPath),0700);err!=nil{return err}
 e:=Event{Seq:g.seq+1,Time:time.Now().UTC().Format(time.RFC3339Nano),
 Engagement:g.policy.EngagementID,Session:session,Tool:tool,Origin:origin,Network:network,
 Allowed:d.Allowed,Reason:d.Reason,ArgsHash:digest([]byte(args)),PrevHash:g.prevHash}
 e.Hash=eventHash(e);b,err:=json.Marshal(e);if err!=nil{return err}
 f,err:=os.OpenFile(g.auditPath,os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);if err!=nil{return err}
 if _,err=f.Write(append(b,'\n'));err!=nil{f.Close();return err}
 if err=f.Sync();err!=nil{f.Close();return err}
 if err=f.Close();err!=nil{return err}
 g.seq,g.prevHash=e.Seq,e.Hash
 return nil
}
// Evaluate denies unrecognized capabilities and mutating browser/shell actions
// in guarded mode. All decisions are logged without full URLs or raw arguments.
func (g *Guard) Evaluate(session,tool,args string)Decision{
 g.mu.Lock();defer g.mu.Unlock()
 d:=Decision{Reason:"tool not authorized for this engagement"}
 network:=false;origin:=""
 switch tool{
 case "read_file","read_document","list_files","glob","grep","todo","skill",
 "session_search","rag_search","review_evidence","investigation_board","inventory_graph","engagement_blackboard","verify_lab_receipts","assess_authz_receipts","compare_authz_fix_receipts","compare_build_bound_fix","auth_workflow_lab","research_next_step","report_finding","triage_finding","add_intel",
 "methodology_status","list_roles","view_image":
  d=Decision{Allowed:true,Reason:"offline tool"}
 case "http_request","web_fetch":
  d=Decision{Reason:"legacy HTTP tool unavailable in guarded mode; use scoped_read"}
 case "scoped_read":
  network=true
  var m map[string]json.RawMessage
  if json.Unmarshal([]byte(args),&m)!=nil{d.Reason="invalid arguments";break}
  var dest,method string
  _=json.Unmarshal(m["url"],&dest);_=json.Unmarshal(m["method"],&method)
  if method==""{method="GET"};method=strings.ToUpper(method)
  var err error;origin,err=parsedOrigin(dest,false)
  if err!=nil||!g.origins[origin]{d.Reason="URL outside approved origin"
  }else if (method!="GET"&&method!="HEAD")||!g.methods[method]{d.Reason="only approved GET/HEAD allowed"
  }else{d=Decision{Allowed:true,Reason:"approved HTTP request"}}
 }
 if network&&d.Allowed{
  if g.total>=g.policy.MaxNetworkCalls{d=Decision{Reason:"request budget exhausted"}
  }else if g.policy.MinIntervalMS>0&&!g.last.IsZero()&&time.Since(g.last)<time.Duration(g.policy.MinIntervalMS)*time.Millisecond{
   d=Decision{Reason:"minimum request interval not reached"}
  }
 }
 if err:=g.appendAudit(session,tool,args,origin,network,d);err!=nil{return Decision{Reason:"audit failure: "+err.Error()}}
 if network&&d.Allowed{g.total++;g.last=time.Now()}
 return d
}
var initOnce sync.Once
var active *Guard
var initErr error
// GateFromEnv is opt-in and fails closed on an invalid manifest. It does not
// constrain plugin side effects, redirects, browsers or OS network activity.
func GateFromEnv(session,tool,args string)Decision{
 p:=strings.TrimSpace(os.Getenv(EnvPolicy))
 if p==""{return Decision{Allowed:true,Reason:"guard not enabled"}}
 initOnce.Do(func(){active,initErr=New(p)})
 if initErr!=nil{return Decision{Reason:"invalid engagement policy: "+initErr.Error()}}
 return active.Evaluate(session,tool,args)
}
func VerifyAudit(path string)(int,error){g,err:=New(path);if err!=nil{return 0,err};return g.seq,nil}

// Manifest returns a validated policy snapshot for the restricted HTTP reader.
func (g *Guard) Manifest() Policy { return g.policy }
