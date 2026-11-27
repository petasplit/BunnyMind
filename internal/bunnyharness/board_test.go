package bunnyharness

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
func baseTasks()[]Task{
 return []Task{
 {ID:"inventory",Title:"Record local test inventory",Kind:"inventory",Priority:5,MaxAttempts:2},
 {ID:"review",Title:"Review observations",Kind:"review",Priority:3,MaxAttempts:2,DependsOn:[]string{"inventory"}},
 {ID:"report",Title:"Write evidence summary",Kind:"report",Priority:1,MaxAttempts:2,DependsOn:[]string{"review"}},
 }
}
func setup(t *testing.T)(*Manager,*time.Time){
 t.Helper()
 tm:=time.Date(2026,11,27,9,0,0,0,time.UTC)
 m:=New(t.TempDir());m.Now=func()time.Time{return tm}
 _,err:=m.Init("test-session",baseTasks(),2);if err!=nil{t.Fatal(err)}
 return m,&tm
}
func digest()string{return strings.Repeat("a",64)}
func TestCycleAndBadDependency(t *testing.T){
 tasks:=baseTasks();tasks[0].DependsOn=[]string{"report"}
 if ValidatePlan(tasks,2)==nil{t.Fatal("cycle accepted")}
 tasks[0].DependsOn=[]string{"does-not-exist"}
 if ValidatePlan(tasks,2)==nil{t.Fatal("unknown dependency accepted")}
}
func TestProgressAndEvidence(t *testing.T){
 m,_:=setup(t)
 a,e:=m.ClaimNext("test-session","worker-1",60);if e!=nil{t.Fatal(e)}
 if a.ID!="inventory"{t.Fatalf("wrong task %+v",a)}
 if _,e:=m.ClaimNext("test-session","worker-2",60);e==nil{t.Fatal("dependent task claimed early")}
 if e:=m.Complete("test-session","worker-1","inventory","short");e==nil{t.Fatal("missing SHA accepted")}
 if e:=m.Complete("test-session","worker-1","inventory",digest());e!=nil{t.Fatal(e)}
 next,e:=m.ClaimNext("test-session","worker-2",60);if e!=nil||next.ID!="review"{t.Fatalf("not ready: %+v %v",next,e)}
}
func TestLeaseExpiryAndRestart(t *testing.T){
 m,tm:=setup(t)
 if _,e:=m.ClaimNext("test-session","worker-1",15);e!=nil{t.Fatal(e)}
 *tm=tm.Add(16*time.Second)
 again:=New(m.Root);again.Now=m.Now
 task,e:=again.ClaimNext("test-session","worker-2",60)
 if e!=nil||task.Attempts!=2{t.Fatalf("reclaimed %+v err=%v",task,e)}
 if e:=again.Complete("test-session","worker-1",task.ID,digest());e==nil{t.Fatal("stale owner completed")}
 *tm=tm.Add(61*time.Second)
 s,e:=again.Status("test-session");if e!=nil{t.Fatal(e)}
 if s.Blocked!=1{t.Fatalf("retries not bounded: %+v",s)}
}
func TestConcurrencyCeiling(t *testing.T){
 tasks:=[]Task{
 {ID:"a",Title:"A",Kind:"analysis",Priority:5,MaxAttempts:2},
 {ID:"b",Title:"B",Kind:"analysis",Priority:4,MaxAttempts:2},
 }
 m:=New(t.TempDir());if _,e:=m.Init("session",tasks,1);e!=nil{t.Fatal(e)}
 if _,e:=m.ClaimNext("session","worker1",60);e!=nil{t.Fatal(e)}
 if _,e:=m.ClaimNext("session","worker2",60);e==nil{t.Fatal("exceeded parallel ceiling")}
}
func TestPriorityAndTieBreak(t *testing.T){
 tasks:=[]Task{
 {ID:"z",Title:"Z",Kind:"analysis",Priority:3,MaxAttempts:1},
 {ID:"a",Title:"A",Kind:"analysis",Priority:3,MaxAttempts:1},
 {ID:"urgent",Title:"High",Kind:"analysis",Priority:5,MaxAttempts:1},
 }
 m:=New(t.TempDir());if _,e:=m.Init("s",tasks,3);e!=nil{t.Fatal(e)}
 for _,want:=range []string{"urgent","a","z"}{
  got,e:=m.ClaimNext("s","worker",60);if e!=nil||got.ID!=want{t.Fatalf("wanted %s got %+v %v",want,got,e)}
 }
}
func TestRetryAndPermanentBlock(t *testing.T){
 m,_:=setup(t)
 a,e:=m.ClaimNext("test-session","worker",60);if e!=nil{t.Fatal(e)}
 if e:=m.Fail("test-session","worker",a.ID,"tool_error");e!=nil{t.Fatal(e)}
 second,e:=m.ClaimNext("test-session","worker",60);if e!=nil||second.Attempts!=2{t.Fatal("not retried")}
 if e:=m.Fail("test-session","worker",a.ID,"timeout");e!=nil{t.Fatal(e)}
 s,e:=m.Status("test-session");if e!=nil||s.Blocked!=1{t.Fatal("not blocked at limit")}
}
func TestHeartbeatRenews(t *testing.T){
 m,tm:=setup(t)
 a,e:=m.ClaimNext("test-session","worker",15);if e!=nil{t.Fatal(e)}
 *tm=tm.Add(14*time.Second)
 if e:=m.Heartbeat("test-session","worker",a.ID,60);e!=nil{t.Fatal(e)}
 *tm=tm.Add(20*time.Second)
 s,e:=m.Status("test-session");if e!=nil||s.Running!=1{t.Fatalf("heartbeat ignored %+v",s)}
}
func TestPlanImmutable(t *testing.T){
 m,_:=setup(t)
 if _,e:=m.Init("test-session",baseTasks(),2);e==nil{t.Fatal("plan overwritten")}
}
func TestSessionHashedPath(t *testing.T){
 m:=New(t.TempDir())
 _,e:=m.Init("../../outside",[]Task{{ID:"safe",Title:"Safe",Kind:"report",Priority:1,MaxAttempts:1}},1)
 if e!=nil{t.Fatal(e)}
 files,e:=os.ReadDir(m.Root);if e!=nil||len(files)!=1{t.Fatal("path escaped")}
 if strings.Contains(files[0].Name(),"/")||len(files[0].Name())!=69{t.Fatal("unsafe filename")}
}
func TestCorruptedStateRefused(t *testing.T){
 m,_:=setup(t)
 path,e:=m.path("test-session");if e!=nil{t.Fatal(e)}
 if e:=os.WriteFile(path,[]byte("not-json"),0600);e!=nil{t.Fatal(e)}
 if _,e:=m.Status("test-session");e==nil{t.Fatal("corrupt file accepted")}
}
func TestAtomicPermissions(t *testing.T){
 m,_:=setup(t)
 path,e:=m.path("test-session");if e!=nil{t.Fatal(e)}
 info,e:=os.Stat(path);if e!=nil{t.Fatal(e)}
 if info.Mode().Perm()!=0600{t.Fatalf("permissions %v",info.Mode().Perm())}
 if filepath.Dir(path)!=m.Root{t.Fatal("out of root")}
}
func TestPersistedContentIsStructured(t *testing.T){
 m,_:=setup(t)
 p,e:=m.path("test-session");if e!=nil{t.Fatal(e)}
 b,e:=os.ReadFile(p);if e!=nil{t.Fatal(e)}
 var board Board
 if json.Unmarshal(b,&board)!=nil||len(board.Tasks)!=3{t.Fatal("bad board state")}
}
