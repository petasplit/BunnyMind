package bunnyharness

import (
 "fmt"
 "testing"
)
func BenchmarkBoardStatus64(b *testing.B){
 tasks:=make([]Task,64)
 for i:=range tasks{
  tasks[i]=Task{ID:fmt.Sprintf("task_%02d",i),Title:"Synthetic inventory review",Kind:"review",Priority:1+(i%5),MaxAttempts:2}
 }
 m:=New(b.TempDir())
 if _,err:=m.Init("performance-fixture",tasks,4);err!=nil{b.Fatal(err)}
 b.ResetTimer()
 for i:=0;i<b.N;i++{
  if _,err:=m.Status("performance-fixture");err!=nil{b.Fatal(err)}
 }
}
