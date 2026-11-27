package bunnygraph

import (
 "fmt"
 "strings"
 "testing"
)
func BenchmarkCompare1024Assets(b *testing.B){
 a:=Snapshot{Version:1,Assets:make([]Asset,1024)}
 for i:=range a.Assets{
  a.Assets[i]=Asset{
   ID:fmt.Sprintf("asset_%04d",i),
   Kind:"endpoint",
   Key:fmt.Sprintf("https://lab.example.test/api/%d",i),
   Fingerprint:strings.Repeat("a",64),
   Source:"captured_http",
  }
 }
 other:=Snapshot{Version:1,Assets:append([]Asset(nil),a.Assets...)}
 other.Assets[100].Fingerprint=strings.Repeat("b",64)
 b.ResetTimer()
 for i:=0;i<b.N;i++{
  diff:=Compare(a,other)
  if len(diff.Changed)!=1{b.Fatal("unstable diff")}
 }
}
