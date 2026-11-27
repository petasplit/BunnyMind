package bunnyblackboard

import (
 "fmt"
 "strings"
 "testing"
)

// BenchmarkSummary128 measures local persisted-board reads and validation.
// It does not benchmark model inference or vulnerability discovery.
func BenchmarkSummary128(b *testing.B) {
 s:=New(b.TempDir())
 for i:=0;i<128;i++ {
  row:=Submission{
   ID:fmt.Sprintf("OBS-%03d",i),
   Kind:"observation",
   Label:"Synthetic observation record",
   Source:"source_inventory",
   EvidenceHash:strings.Repeat("a",64),
  }
  if _,_,err:=s.RecordSubmission("synthetic-benchmark","agent",row);err!=nil{b.Fatal(err)}
 }
 b.ResetTimer()
 for i:=0;i<b.N;i++ {
  x,err:=s.Summary("synthetic-benchmark",50)
  if err!=nil||x.Count!=128{b.Fatalf("summary failed: %v",err)}
 }
}
