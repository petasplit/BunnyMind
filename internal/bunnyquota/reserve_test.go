package bunnyquota

import (
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "sync"
 "testing"
)
func TestCrossProcessStyleBudgetReservationsNeverOverrun(t *testing.T){
 dir:=t.TempDir()
 ctx:=context.Background()
 const maximum=20
 var wg sync.WaitGroup
 successes:=make(chan bool,16)
 for i:=0;i<16;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   _,err:=Reserve(ctx,dir,"approved-fixture",3,maximum)
   successes<-err==nil
  }()
 }
 wg.Wait();close(successes)
 count:=0
 for ok:=range successes{if ok{count++}}
 if count!=6{t.Fatalf("expected exactly six reservations (18/20), got %d",count)}
 ledger,err:=Read(dir,"approved-fixture")
 if err!=nil||ledger.RequestsReserved!=18{
  t.Fatalf("unexpected persisted quota %+v %v",ledger,err)
 }
 if _,err:=Reserve(ctx,dir,"approved-fixture",3,maximum);err==nil{
  t.Fatal("request budget was overrun")
 }
 if _,err:=Reserve(ctx,dir,"approved-fixture",2,maximum);err!=nil{
  t.Fatalf("remaining capacity unavailable: %v",err)
 }
 if _,err:=Reserve(ctx,dir,"approved-fixture",1,maximum);err==nil{
  t.Fatal("budget not exhausted after final reservation")
 }
}
func TestCorruptQuotaLedgerFailsClosed(t *testing.T){
 dir:=t.TempDir()
 if _,err:=Reserve(context.Background(),dir,"engagement-a",1,5);err!=nil{t.Fatal(err)}
 ledgerPath,_:=paths(dir,"engagement-a")
 if err:=os.WriteFile(ledgerPath,[]byte("{corrupted"),0600);err!=nil{t.Fatal(err)}
 if _,err:=Reserve(context.Background(),dir,"engagement-a",1,5);err==nil{
  t.Fatal("corrupt request budget allowed more network activity")
 }
}
func TestHeldLockDeniesSecondProcess(t *testing.T){
 dir:=t.TempDir()
 _,lockPath:=paths(dir,"engagement-a")
 if err:=os.WriteFile(lockPath,[]byte("active-worker"),0600);err!=nil{t.Fatal(err)}
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 if _,err:=Reserve(ctx,dir,"engagement-a",1,5);err==nil{
  t.Fatal("held lock allowed concurrent network budget modification")
 }
 if _,err:=os.Stat(filepath.Join(dir,filepath.Base(lockPath)));err!=nil{t.Fatal(err)}
 os.Remove(lockPath)
 if _,err:=Reserve(context.Background(),dir,"engagement-a",1,5);err!=nil{t.Fatal(err)}
}
func TestReservedBudgetNeverRefillsAfterCrashLikeFailure(t *testing.T){
 dir:=t.TempDir()
 got,err:=Reserve(context.Background(),dir,"engagement-b",4,5)
 if err!=nil||got.Total!=4{t.Fatalf("reservation failed %+v %v",got,err)}
 // Re-open from a new reader; there is no automatic refund.
 data,err:=os.ReadFile(filepath.Join(dir,got.LedgerFile))
 if err!=nil||!strings.Contains(string(data),"requests_reserved"){t.Fatal("budget metadata missing")}
 var ledger Ledger
 if json.Unmarshal(data,&ledger)!=nil||ledger.RequestsReserved!=4{t.Fatal("persisted budget was not charged")}
}
