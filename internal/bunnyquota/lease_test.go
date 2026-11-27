package bunnyquota

import (
 "context"
 "errors"
 "testing"
 "time"
)
func TestExecutionLeaseSerializesApprovedPythonRuns(t *testing.T){
 root:=t.TempDir()
 release,err:=ExecutionLease(context.Background(),root,"private-engagement")
 if err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithTimeout(context.Background(),120*time.Millisecond)
 defer cancel()
 if _,err:=ExecutionLease(ctx,root,"private-engagement");!errors.Is(err,context.DeadlineExceeded){
  t.Fatalf("overlapping Python run was allowed or wrong failure: %v",err)
 }
 release()
 release() // harmless repeated cleanup
 finish,err:=ExecutionLease(context.Background(),root,"private-engagement")
 if err!=nil{t.Fatalf("lease remained locked after completion: %v",err)}
 finish()
}
func TestExecutionLeaseIsScopedToEngagement(t *testing.T){
 root:=t.TempDir()
 a,err:=ExecutionLease(context.Background(),root,"assessment-a")
 if err!=nil{t.Fatal(err)}
 defer a()
 b,err:=ExecutionLease(context.Background(),root,"assessment-b")
 if err!=nil{t.Fatal("separate engagement was incorrectly blocked")}
 b()
}
