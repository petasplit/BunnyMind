// Package bunnyharness persists bounded investigation tasks and their
// dependencies. It is a coordination ledger, not an autonomous executor.
package bunnyharness

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strings"
 "sync"
 "time"
)

const (
 Queued="queued"
 Running="running"
 Done="done"
 Blocked="blocked"
 MaxTasks=128
)
var idPattern=regexp.MustCompile("^[A-Za-z0-9_-]{1,48}$")
var shaPattern=regexp.MustCompile("^[0-9a-f]{64}$")
var validKinds=map[string]bool{
 "inventory":true,"analysis":true,"verification":true,
 "review":true,"report":true,"remediation":true,
}

type Task struct {
 ID string `json:"id"`
 Title string `json:"title"`
 Kind string `json:"kind"`
 Priority int `json:"priority"`
 DependsOn []string `json:"depends_on,omitempty"`
 MaxAttempts int `json:"max_attempts"`
 State string `json:"state"`
 Attempts int `json:"attempts"`
 Owner string `json:"owner,omitempty"`
 LeaseUntil time.Time `json:"lease_until,omitempty"`
 EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
 FailureCode string `json:"failure_code,omitempty"`
}
type Board struct {
 Version int `json:"version"`
 MaxParallel int `json:"max_parallel"`
 Tasks []Task `json:"tasks"`
 UpdatedAt time.Time `json:"updated_at"`
}
type Summary struct {
 Board Board `json:"board"`
 Ready []string `json:"ready"`
 Queued int `json:"queued"`
 Running int `json:"running"`
 Done int `json:"done"`
 Blocked int `json:"blocked"`
}
type Manager struct {
 Root string
 Mu sync.Mutex
 Now func()time.Time
}
func New(root string)*Manager{return &Manager{Root:root,Now:time.Now}}
func (m *Manager) now()time.Time{if m.Now!=nil{return m.Now().UTC()};return time.Now().UTC()}
func sessionName(session string)(string,error){
 if strings.TrimSpace(session)==""{return "",errors.New("session ID missing")}
 h:=sha256.Sum256([]byte(session))
 return hex.EncodeToString(h[:])+".json",nil
}
func (m *Manager) path(session string)(string,error){
 name,err:=sessionName(session);if err!=nil{return "",err}
 return filepath.Join(m.Root,name),nil
}
func ValidatePlan(tasks []Task, maxParallel int)error{
 if len(tasks)==0||len(tasks)>MaxTasks{return fmt.Errorf("plan requires 1..%d tasks",MaxTasks)}
 if maxParallel<1||maxParallel>8{return errors.New("max_parallel must be between 1 and 8")}
 ids:=map[string]bool{}
 for _,t:=range tasks{
  if !idPattern.MatchString(t.ID)||ids[t.ID]{return fmt.Errorf("invalid/duplicate task ID %q",t.ID)}
  ids[t.ID]=true
  if strings.TrimSpace(t.Title)==""||len(t.Title)>160||strings.ContainsAny(t.Title,"\r\n"){
   return fmt.Errorf("task %s: invalid title",t.ID)
  }
  if !validKinds[t.Kind]{return fmt.Errorf("task %s: unknown kind %s",t.ID,t.Kind)}
  if t.Priority<1||t.Priority>5{return fmt.Errorf("task %s: priority must be 1..5",t.ID)}
  if t.MaxAttempts<1||t.MaxAttempts>5{return fmt.Errorf("task %s: max_attempts must be 1..5",t.ID)}
  if len(t.DependsOn)>16{return fmt.Errorf("task %s: too many dependencies",t.ID)}
 }
 deps:=map[string][]string{}
 for _,t:=range tasks{
  seen:=map[string]bool{}
  for _,d:=range t.DependsOn{
   if !ids[d]||d==t.ID||seen[d] {return fmt.Errorf("task %s: invalid dependency %q",t.ID,d)}
   seen[d]=true
  }
  deps[t.ID]=t.DependsOn
 }
 color:=map[string]int{}
 var visit func(string)error
 visit=func(id string)error{
  if color[id]==1{return fmt.Errorf("dependency cycle at %s",id)}
  if color[id]==2{return nil}
  color[id]=1
  for _,d:=range deps[id]{if err:=visit(d);err!=nil{return err}}
  color[id]=2
  return nil
 }
 for _,t:=range tasks{if err:=visit(t.ID);err!=nil{return err}}
 return nil
}
func validateBoard(b Board)error{
 if b.Version!=1{return errors.New("unsupported board format")}
 if err:=ValidatePlan(b.Tasks,b.MaxParallel);err!=nil{return err}
 for _,t:=range b.Tasks{
  if t.Attempts<0||t.Attempts>t.MaxAttempts{return fmt.Errorf("task %s: invalid attempt count",t.ID)}
  switch t.State{
  case Queued:
   if t.Owner!=""||t.EvidenceSHA256!=""{return fmt.Errorf("task %s: queued task has owner/evidence",t.ID)}
  case Running:
   if t.Owner==""||t.LeaseUntil.IsZero()||t.Attempts==0{return fmt.Errorf("task %s: running task missing lease",t.ID)}
  case Done:
   if !shaPattern.MatchString(t.EvidenceSHA256){return fmt.Errorf("task %s: completion requires SHA256",t.ID)}
  case Blocked:
  default:return fmt.Errorf("task %s: invalid state %q",t.ID,t.State)
  }
 }
 return nil
}
func (m *Manager) load(session string)(Board,error){
 path,err:=m.path(session);if err!=nil{return Board{},err}
 data,err:=os.ReadFile(path);if err!=nil{return Board{},err}
 var b Board
 if err:=json.Unmarshal(data,&b);err!=nil{return Board{},fmt.Errorf("board corrupt: %w",err)}
 if err:=validateBoard(b);err!=nil{return Board{},fmt.Errorf("board invalid: %w",err)}
 return b,nil
}
func (m *Manager) save(session string,b Board)error{
 if err:=validateBoard(b);err!=nil{return err}
 path,err:=m.path(session);if err!=nil{return err}
 if err:=os.MkdirAll(m.Root,0700);err!=nil{return err}
 b.UpdatedAt=m.now()
 data,err:=json.MarshalIndent(b,"","  ");if err!=nil{return err}
 f,err:=os.CreateTemp(m.Root,".bunnymind-*");if err!=nil{return err}
 temp:=f.Name()
 defer os.Remove(temp)
 if err:=f.Chmod(0600);err!=nil{f.Close();return err}
 if _,err:=f.Write(append(data,'\n'));err!=nil{f.Close();return err}
 if err:=f.Sync();err!=nil{f.Close();return err}
 if err:=f.Close();err!=nil{return err}
 return os.Rename(temp,path)
}
func (m *Manager) Init(session string,tasks []Task,maxParallel int)(Board,error){
 m.Mu.Lock();defer m.Mu.Unlock()
 if err:=ValidatePlan(tasks,maxParallel);err!=nil{return Board{},err}
 path,err:=m.path(session);if err!=nil{return Board{},err}
 if _,err:=os.Stat(path);err==nil{return Board{},errors.New("plan already exists; cannot overwrite active investigation")
 }else if !os.IsNotExist(err){return Board{},err}
 copied:=make([]Task,len(tasks))
 for i,t:=range tasks{
  copied[i]=Task{ID:t.ID,Title:t.Title,Kind:t.Kind,Priority:t.Priority,MaxAttempts:t.MaxAttempts,State:Queued,DependsOn:append([]string(nil),t.DependsOn...)}
 }
 b:=Board{Version:1,MaxParallel:maxParallel,Tasks:copied,UpdatedAt:m.now()}
 return b,m.save(session,b)
}
func index(b *Board)map[string]*Task{
 x:=make(map[string]*Task,len(b.Tasks))
 for i:=range b.Tasks{x[b.Tasks[i].ID]=&b.Tasks[i]}
 return x
}
func expire(b *Board,now time.Time)bool{
 changed:=false
 for i:=range b.Tasks{
  t:=&b.Tasks[i]
  if t.State!=Running||now.Before(t.LeaseUntil){continue}
  if t.Attempts>=t.MaxAttempts{t.State=Blocked;t.FailureCode="lease_expired"
  }else{t.State=Queued;t.FailureCode="lease_expired"}
  t.Owner="";t.LeaseUntil=time.Time{};changed=true
 }
 return changed
}
func readyTasks(b *Board)[]int{
 tasks:=index(b)
 ready:=[]int{}
 for i:=range b.Tasks{
  t:=&b.Tasks[i];if t.State!=Queued{continue}
  ok:=true
  for _,id:=range t.DependsOn{if tasks[id].State!=Done{ok=false;break}}
  if ok{ready=append(ready,i)}
 }
 sort.Slice(ready,func(i,j int)bool{
  a,c:=b.Tasks[ready[i]],b.Tasks[ready[j]]
  if a.Priority!=c.Priority{return a.Priority>c.Priority}
  return a.ID<c.ID
 })
 return ready
}
func countRunning(b *Board)int{n:=0;for _,t:=range b.Tasks{if t.State==Running{n++}};return n}
func validLease(seconds int)error{
 if seconds<15||seconds>900{return errors.New("lease_seconds must be 15..900")}
 return nil
}
// ClaimNext leases one eligible task to a caller, without running it.
// The owner must be the trusted session identity, never a model-supplied value.
func (m *Manager) ClaimNext(session,owner string,seconds int)(Task,error){
 m.Mu.Lock();defer m.Mu.Unlock()
 if owner==""{return Task{},errors.New("owner missing")}
 if err:=validLease(seconds);err!=nil{return Task{},err}
 b,err:=m.load(session);if err!=nil{return Task{},err}
 now:=m.now();changed:=expire(&b,now)
 if countRunning(&b)>=b.MaxParallel{
  if changed{_ = m.save(session,b)}
  return Task{},errors.New("parallel task limit reached")
 }
 ready:=readyTasks(&b)
 if len(ready)==0{
  if changed{if err:=m.save(session,b);err!=nil{return Task{},err}}
  return Task{},errors.New("no ready tasks; dependencies, retries or review may be pending")
 }
 t:=&b.Tasks[ready[0]]
 t.State=Running;t.Attempts++;t.Owner=owner;t.LeaseUntil=now.Add(time.Duration(seconds)*time.Second)
 t.FailureCode=""
 out:=*t
 if err:=m.save(session,b);err!=nil{return Task{},err}
 return out,nil
}
func (m *Manager) activeTask(session,id,owner string)(Board,*Task,error){
 b,err:=m.load(session);if err!=nil{return Board{},nil,err}
 expire(&b,m.now())
 for i:=range b.Tasks{
  t:=&b.Tasks[i]
  if t.ID==id{
   if t.State!=Running||t.Owner!=owner||owner==""{return Board{},nil,errors.New("task is not actively leased to this session")}
   return b,t,nil
  }
 }
 return Board{},nil,errors.New("unknown task ID")
}
func (m *Manager) Complete(session,owner,id,evidence string)error{
 m.Mu.Lock();defer m.Mu.Unlock()
 if !shaPattern.MatchString(evidence){return errors.New("completion requires a lowercase 64-character SHA-256 evidence digest")}
 b,task,err:=m.activeTask(session,id,owner);if err!=nil{return err}
 task.State=Done;task.EvidenceSHA256=evidence;task.Owner="";task.LeaseUntil=time.Time{}
 return m.save(session,b)
}
func (m *Manager) Fail(session,owner,id,code string)error{
 m.Mu.Lock();defer m.Mu.Unlock()
 switch code{case "timeout","tool_error","blocked","insufficient_evidence":default:return errors.New("invalid failure code")}
 b,task,err:=m.activeTask(session,id,owner);if err!=nil{return err}
 if code=="blocked"||task.Attempts>=task.MaxAttempts{task.State=Blocked}else{task.State=Queued}
 task.Owner="";task.LeaseUntil=time.Time{};task.FailureCode=code
 return m.save(session,b)
}
func (m *Manager) Heartbeat(session,owner,id string,seconds int)error{
 m.Mu.Lock();defer m.Mu.Unlock()
 if err:=validLease(seconds);err!=nil{return err}
 b,task,err:=m.activeTask(session,id,owner);if err!=nil{return err}
 task.LeaseUntil=m.now().Add(time.Duration(seconds)*time.Second)
 return m.save(session,b)
}
func (m *Manager) Status(session string)(Summary,error){
 m.Mu.Lock();defer m.Mu.Unlock()
 b,err:=m.load(session);if err!=nil{return Summary{},err}
 if expire(&b,m.now()){if err:=m.save(session,b);err!=nil{return Summary{},err}}
 s:=Summary{Board:b,Ready:[]string{}}
 for _,t:=range b.Tasks{switch t.State{
  case Queued:s.Queued++
  case Running:s.Running++
  case Done:s.Done++
  case Blocked:s.Blocked++
 }}
 for _,i:=range readyTasks(&b){s.Ready=append(s.Ready,b.Tasks[i].ID)}
 return s,nil
}
