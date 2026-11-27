package bunnyplanner

import (
 "encoding/json"
 "reflect"
 "strings"
 "testing"
)
func TestPriorityAndLimit(t *testing.T){
 plan,err:=Build(ChangeSet{
  Added:[]string{"a","b"},Changed:[]string{"z"},Removed:[]string{"old"},
  AddedLinks:[]string{"a|calls|z"},
 },3)
 if err!=nil{t.Fatal(err)}
 if len(plan.Tasks)!=3||plan.Dropped!=2||plan.Tasks[0].Priority!=5||
  plan.Tasks[1].Priority!=4||plan.Tasks[2].Priority!=4{t.Fatalf("incorrect plan %+v",plan)}
}
func TestStableAcrossOrdering(t *testing.T){
 a,err:=Build(ChangeSet{Added:[]string{"c","a","b"},Changed:[]string{"z"}},10)
 if err!=nil{t.Fatal(err)}
 b,err:=Build(ChangeSet{Added:[]string{"b","c","a"},Changed:[]string{"z"}},10)
 if err!=nil||!reflect.DeepEqual(a.Tasks,b.Tasks){t.Fatal("unstable task IDs or order")}
}
func TestDedupAndChangePrecedence(t *testing.T){
 p,err:=Build(ChangeSet{Changed:[]string{"x","x"},Added:[]string{"x"}},10)
 if err!=nil||p.TotalChanges!=1||p.Tasks[0].Priority!=5{t.Fatal("dup inflated score")}
}
func TestInvalidAssetsAndRelations(t *testing.T){
 for _,c:=range []ChangeSet{
  {Added:[]string{"https://other.example"}},
  {Changed:[]string{"a/b"}},
  {AddedLinks:[]string{"a|invalid|b"}},
  {RemovedLinks:[]string{"a|calls|missing|unexpected"}},
 }{
  if _,err:=Build(c,10);err==nil{t.Fatalf("accepted invalid diff %+v",c)}
 }
}
func TestLimitBounds(t *testing.T){
 if _,err:=Build(ChangeSet{},0);err==nil{t.Fatal("zero limit")}
 if _,err:=Build(ChangeSet{},65);err==nil{t.Fatal("limit overflow")}
}
func TestEmptyDiff(t *testing.T){
 p,err:=Build(ChangeSet{},20)
 if err!=nil||len(p.Tasks)!=0||p.Dropped!=0{t.Fatalf("%+v %v",p,err)}
}
func TestTaskSchemaCompatible(t *testing.T){
 p,err:=Build(ChangeSet{Changed:[]string{"endpoint_A"}},20)
 if err!=nil{t.Fatal(err)}
 b,err:=json.Marshal(p.Tasks[0])
 if err!=nil{t.Fatal(err)}
 for _,field:=range []string{"id","title","kind","priority","max_attempts"}{
  if !strings.Contains(string(b),`"`+field+`"`){t.Fatalf("field %s absent",field)}
 }
}
func TestNoAssetNameLeakedInTaskTitle(t *testing.T){
 p,err:=Build(ChangeSet{Added:[]string{"private_asset_123"}},20)
 if err!=nil{t.Fatal(err)}
 if strings.Contains(p.Tasks[0].Title,"private_asset_123"){t.Fatal("raw ID in title")}
}
