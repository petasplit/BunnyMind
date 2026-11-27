package bunnyidentity

import (
 "encoding/json"
 "errors"
 "fmt"
 "strings"
 "testing"
 "time"
)
const first="synthetic_owner_0123456789abcdef0123456789"
const second="synthetic_foreign_abcdef0123456789abcdef0123"
func TestIsolatedRoles(t *testing.T){
 v:=New();defer v.Close()
 if err:=v.Add("owner",first,"resource_1111",time.Minute);err!=nil{t.Fatal(err)}
 if err:=v.Add("foreign",second,"resource_2222",time.Minute);err!=nil{t.Fatal(err)}
 if v.Count()!=2{t.Fatal("identity count")}
 if err:=v.Use("owner",func(token,resource string)error{
  if token!=first||resource!="resource_1111"{t.Fatal("owner confused with foreign")}
  return nil
 });err!=nil{t.Fatal(err)}
 if err:=v.Use("foreign",func(token,resource string)error{
  if token!=second||resource!="resource_2222"{t.Fatal("foreign confused with owner")}
  return nil
 });err!=nil{t.Fatal(err)}
}
func TestNoTokenInSerializationOrError(t *testing.T){
 v:=New();defer v.Close()
 if err:=v.Add("owner",first,"resource_1111",time.Minute);err!=nil{t.Fatal(err)}
 view,err:=v.View("owner");if err!=nil{t.Fatal(err)}
 raw,_:=json.Marshal(view)
 if strings.Contains(string(raw),first)||strings.Contains(fmt.Sprint(v),first){t.Fatal("token leaked")}
 callbackErr:=v.Use("owner",func(token,resource string)error{return errors.New("leak:"+token)})
 if callbackErr==nil||strings.Contains(callbackErr.Error(),first){t.Fatal("callback leaked token")}
}
func TestRotationRequiresFreshToken(t *testing.T){
 v:=New();defer v.Close()
 if err:=v.Add("owner",first,"resource_1111",time.Minute);err!=nil{t.Fatal(err)}
 if err:=v.Rotate("owner","wrong",second,time.Minute);err==nil{t.Fatal("stale rotation accepted")}
 if err:=v.Rotate("owner",first,first,time.Minute);err==nil{t.Fatal("same token accepted")}
 if err:=v.Rotate("owner",first,second,time.Minute);err!=nil{t.Fatal(err)}
 view,_:=v.View("owner")
 if view.Generation!=2{t.Fatal("generation not bumped")}
 if err:=v.Use("owner",func(token,resource string)error{
  if token!=second{t.Fatal("new bearer token not installed")}
  return nil
 });err!=nil{t.Fatal(err)}
}
func TestCannotOverwriteIdentity(t *testing.T){
 v:=New();defer v.Close()
 if err:=v.Add("owner",first,"resource_1111",time.Minute);err!=nil{t.Fatal(err)}
 if err:=v.Add("owner",second,"resource_2222",time.Minute);err==nil{t.Fatal("account overwrite allowed")}
}
func TestBudgetAndRevoke(t *testing.T){
 v:=New();defer v.Close()
 for i:=0;i<MaxIdentities;i++{
  if err:=v.Add(fmt.Sprintf("test_%d",i),first,fmt.Sprintf("resource_%d",1000+i),time.Minute);err!=nil{t.Fatal(err)}
 }
 if err:=v.Add("extra",second,"resource_9999",time.Minute);err==nil{t.Fatal("quota bypassed")}
 v.Revoke("test_0")
 if err:=v.Add("extra",second,"resource_9999",time.Minute);err!=nil{t.Fatal(err)}
}
func TestExpiredSessionRejected(t *testing.T){
 v:=New();defer v.Close()
 now:=time.Now().UTC()
 v.now=func()time.Time{return now}
 if err:=v.Add("owner",first,"resource_1111",time.Minute);err!=nil{t.Fatal(err)}
 now=now.Add(61*time.Second)
 if err:=v.Use("owner",func(token,resource string)error{return nil});err==nil{t.Fatal("expired access")}
 view,err:=v.View("owner");if err!=nil||view.HasSession{t.Fatal("expired role still active")}
}
func TestCloseRevokesEverything(t *testing.T){
 v:=New()
 if err:=v.Add("owner",first,"resource_1111",time.Minute);err!=nil{t.Fatal(err)}
 v.Close()
 if v.Count()!=0{t.Fatal("close failed")}
 if err:=v.Add("foreign",second,"resource_2222",time.Minute);err==nil{t.Fatal("closed vault reopened")}
}
func TestMinMaxLease(t *testing.T){
 v:=New();defer v.Close()
 if err:=v.Add("owner",first,"resource_1111",time.Second);err==nil{t.Fatal("tiny ttl accepted")}
 if err:=v.Add("owner",first,"resource_1111",31*time.Minute);err==nil{t.Fatal("oversize ttl accepted")}
}
