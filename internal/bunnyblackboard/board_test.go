package bunnyblackboard
import("encoding/json";"os";"strings";"sync";"testing")
func testDigest()string{return strings.Repeat("a",64)}
func sample()Submission{return Submission{ID:"OBS-001",Kind:"observation",AssetID:"API-1",Label:"Synthetic response differs",Source:"captured_http",EvidenceHash:testDigest()}}
func TestCrossAgentAndRestart(t *testing.T){
 root:=t.TempDir();a:=New(root)
 if _,ok,e:=a.RecordSubmission("engagement-a","agent-1",sample());e!=nil||!ok{t.Fatalf("record %v",e)}
 b:=New(root)
 x,e:=b.Summary("engagement-a",50);if e!=nil||x.Count!=1||x.Records[0].State!=StateOpen{t.Fatal("cross-session read failed")}
 if _,e:=b.Review("engagement-a","agent-1","OBS-001",StateReproduction,"crosscheck");e==nil{t.Fatal("self review")}
 if _,e:=b.Review("engagement-a","agent-2","OBS-001",StateReproduction,"crosscheck");e!=nil{t.Fatal(e)}
 x,e=a.Summary("engagement-a",50);if e!=nil||x.ByState[StateReproduction]!=1{t.Fatal("restart lost review")}
 if _,e:=a.Review("engagement-a","agent-3","OBS-001",StateRejected,"stale");e==nil{t.Fatal("review overwritten")}
}
func TestEngagementSeparation(t *testing.T){
 s:=New(t.TempDir());_,_,_=s.RecordSubmission("one","agent",sample());x,e:=s.Summary("two",50)
 if e!=nil||x.Count!=0{t.Fatal("shared unrelated engagement")}
}
func TestIdempotentConflict(t *testing.T){
 s:=New(t.TempDir());_,ok,e:=s.RecordSubmission("e","a",sample());if e!=nil||!ok{t.Fatal(e)}
 _,ok,e=s.RecordSubmission("e","a",sample());if e!=nil||ok{t.Fatal("duplicate not idempotent")}
 v:=sample();v.Label="different"
 if _,_,e=s.RecordSubmission("e","a",v);e==nil{t.Fatal("silent rewrite")}
}
func TestRejectBadSourceAndSecrets(t *testing.T){
 s:=New(t.TempDir())
 for _,v:=range []Submission{
 {ID:"x",Kind:"observation",Label:"token=sample",Source:"operator",EvidenceHash:testDigest()},
 {ID:"y",Kind:"observation",Label:"safe",Source:"verified",EvidenceHash:testDigest()},
 {ID:"z",Kind:"verified",Label:"safe",Source:"operator",EvidenceHash:testDigest()},
 {ID:"w",Kind:"observation",Label:"safe",Source:"operator",EvidenceHash:"short"},
 }{
  if _,_,e:=s.RecordSubmission("e","agent",v);e==nil{t.Fatalf("bad input accepted %+v",v)}
 }
}
func TestReviewCannotBeVerified(t *testing.T){
 s:=New(t.TempDir());_,_,_=s.RecordSubmission("e","a",sample())
 if _,e:=s.Review("e","b","OBS-001","verified","crosscheck");e==nil{t.Fatal("fake verification")}
}
func TestBudget(t *testing.T){
 s:=New(t.TempDir())
 for i:=0;i<MaxEntries;i++{
  v:=sample();v.ID="item-"+string(rune('a'+i/26))+string(rune('a'+i%26))
  if _,_,e:=s.RecordSubmission("e","a",v);e!=nil{t.Fatalf("item %d: %v",i,e)}
 }
 v:=sample();v.ID="EXTRA"
 if _,_,e:=s.RecordSubmission("e","a",v);e==nil{t.Fatal("budget ignored")}
}
func TestParallelRecords(t *testing.T){
 s:=New(t.TempDir());var wg sync.WaitGroup
 for i:=0;i<20;i++{
  wg.Add(1)
  go func(i int){defer wg.Done();v:=sample();v.ID="OBJ-"+string(rune('A'+i));_,_,_=s.RecordSubmission("e","agent",v)}(i)
 }
 wg.Wait();out,e:=s.Summary("e",0);if e!=nil||out.Count!=20{t.Fatalf("lost records %v %+v",e,out)}
}
func TestCorruptionNotOverwritten(t *testing.T){
 s:=New(t.TempDir());_,_,_=s.RecordSubmission("e","a",sample())
 path,_:=s.path("e");_=os.WriteFile(path,[]byte("oops"),0600)
 v:=sample();v.ID="NEW"
 if _,_,e:=s.RecordSubmission("e","a",v);e==nil{t.Fatal("overwrote corrupt state")}
}
func TestNoSessionIDInOutput(t *testing.T){
 s:=New(t.TempDir());_,_,_=s.RecordSubmission("e","private-session",sample())
 out,_:=s.Summary("e",50);b,_:=json.Marshal(out)
 if strings.Contains(string(b),"private-session"){t.Fatal("leaked raw session")}
}
func TestLimit(t *testing.T){if _,e:=New(t.TempDir()).Summary("e",51);e==nil{t.Fatal("unbounded listing")}}
