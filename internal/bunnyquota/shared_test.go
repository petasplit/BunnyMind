package bunnyquota

import (
 "context"
 "path/filepath"
 "sync"
 "testing"
)

func TestGlobalLedgerResistsEvidenceDirectoryChanges(t *testing.T){
 dir:=t.TempDir()
 t.Setenv("BUNNY_SHARED_QUOTA_ROOT",dir)
 ctx:=context.Background()
 if _,err:=ReserveShared(ctx,"research01",3,6);err!=nil{t.Fatal(err)}
 if _,err:=ReserveShared(ctx,"research01",3,6);err!=nil{t.Fatal(err)}
 if _,err:=ReserveShared(ctx,"research01",1,6);err==nil{
  t.Fatal("different caller should not recover exhausted shared budget")
 }
 ledger,err:=Read(dir,"research01")
 if err!=nil||ledger.RequestsReserved!=6{t.Fatalf("global quota lost: %+v %v",ledger,err)}
}
func TestConcurrentSharedReservationsCannotOverspend(t *testing.T){
 dir:=t.TempDir()
 t.Setenv("BUNNY_SHARED_QUOTA_ROOT",dir)
 var wg sync.WaitGroup
 successes:=make(chan bool,30)
 for i:=0;i<30;i++{wg.Add(1);go func(){
  defer wg.Done()
  _,err:=ReserveShared(context.Background(),"shared01",1,9)
  successes<-err==nil
 }()}
 wg.Wait();close(successes)
 total:=0
 for ok:=range successes{if ok{total++}}
 if total!=9{t.Fatalf("expected exactly nine granted requests, got %d",total)}
}
func TestRejectNonabsoluteSharedRoot(t *testing.T){
 t.Setenv("BUNNY_SHARED_QUOTA_ROOT","../different")
 if _,err:=SharedRoot();err==nil{t.Fatal("relative network ledger root allowed")}
 t.Setenv("BUNNY_SHARED_QUOTA_ROOT",t.TempDir())
 root,err:=SharedRoot()
 if err!=nil||!filepath.IsAbs(root){t.Fatalf("invalid shared root %q: %v",root,err)}
}
