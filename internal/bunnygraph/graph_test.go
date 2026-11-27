package bunnygraph

import (
 "encoding/json"
 "os"
 "strings"
 "testing"
)
func sha()string{return strings.Repeat("b",64)}
func one()Snapshot{
 return Snapshot{Version:1,Assets:[]Asset{
  {ID:"api",Kind:"origin",Key:"https://api.example.test",Fingerprint:sha(),Source:"user_supplied"},
  {ID:"users",Kind:"endpoint",Key:"https://api.example.test/users",Fingerprint:sha(),Source:"captured_http"},
 },Links:[]Link{{From:"api",To:"users",Relation:"contains"}}}
}
func TestInitialSnapshot(t *testing.T){
 s:=New(t.TempDir())
 diff,err:=s.Update("session",one())
 if err!=nil||!diff.FirstSnapshot||len(diff.Added)!=2||len(diff.AddedLinks)!=1{
  t.Fatalf("unexpected initial %+v %v",diff,err)
 }
}
func TestNoChange(t *testing.T){
 s:=New(t.TempDir());_,_ = s.Update("session",one())
 result,err:=s.Update("session",one())
 if err!=nil||result.Unchanged!=2||len(result.Changed)!=0||len(result.Added)!=0{
  t.Fatalf("unexpected %+v %v",result,err)
 }
}
func TestChangeAndRemoval(t *testing.T){
 s:=New(t.TempDir());_,_ = s.Update("session",one())
 n:=one();n.Assets[0].Fingerprint=strings.Repeat("a",64);n.Assets=n.Assets[:1];n.Links=nil
 diff,err:=s.Update("session",n)
 if err!=nil||len(diff.Changed)!=1||diff.Changed[0]!="api"||len(diff.Removed)!=1||
 diff.Removed[0]!="users"||len(diff.RemovedLinks)!=1{t.Fatalf("diff %+v %v",diff,err)}
}
func TestInvalidEdge(t *testing.T){
 n:=one();n.Links[0].To="not-in-snapshot"
 if Validate(n)==nil{t.Fatal("dangling relationship accepted")}
}
func TestDuplicateNodeOrEdge(t *testing.T){
 n:=one();n.Assets=append(n.Assets,n.Assets[0])
 if Validate(n)==nil{t.Fatal("duplicate asset accepted")}
 n=one();n.Links=append(n.Links,n.Links[0])
 if Validate(n)==nil{t.Fatal("duplicate link accepted")}
}
func TestSecretBearingURLRejected(t *testing.T){
 for _,key:=range []string{"https://user:pw@host.test/","https://host.test/users?token=abc","https://host.test/#fragment"}{
  n:=one();n.Assets[0].Key=key
  if Validate(n)==nil{t.Fatalf("secret URL allowed %s",key)}
 }
}
func TestInputSourceNotTreatedAsVerified(t *testing.T){
 n:=one();n.Assets[0].Source="independently_verified"
 if Validate(n)==nil{t.Fatal("unrecognized provenance accepted")}
}
func TestPersistenceAndSummary(t *testing.T){
 root:=t.TempDir()
 s:=New(root);_,err:=s.Update("first",one());if err!=nil{t.Fatal(err)}
 again:=New(root)
 summary,err:=again.Summary("first")
 if err!=nil||summary.Assets!=2||summary.Links!=1||summary.BySource["captured_http"]!=1{
  t.Fatalf("%+v %v",summary,err)
 }
 if _,err:=again.Summary("second");err==nil{t.Fatal("different session should not see snapshot")}
}
func TestNoRawKeysInDiff(t *testing.T){
 s:=New(t.TempDir());diff,err:=s.Update("x",one());if err!=nil{t.Fatal(err)}
 b,_:=json.Marshal(diff)
 if strings.Contains(string(b),"api.example.test"){t.Fatal("raw asset key leaked in diff")}
}
func TestCorruptInventoryRejected(t *testing.T){
 s:=New(t.TempDir());_,_ = s.Update("x",one())
 path,err:=s.path("x");if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,[]byte("BAD"),0600);err!=nil{t.Fatal(err)}
 if _,err:=s.Update("x",one());err==nil{t.Fatal("corruption overwritten")}
}
