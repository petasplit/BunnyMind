// Package bunnyquota provides fail-closed cross-process reservation of
// Python proof requests sharing one operator-controlled evidence directory.
// Reserved requests count against the manifest even when a process crashes.
package bunnyquota

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
 "time"
)
type Ledger struct{
 Version int `json:"version"`
 EngagementID string `json:"engagement_id"`
 RequestsReserved int `json:"requests_reserved"`
 UpdatedAt string `json:"updated_at"`
}
type Receipt struct{
 Before int `json:"before"`
 Reserved int `json:"reserved"`
 Total int `json:"total"`
 Maximum int `json:"maximum"`
 LedgerFile string `json:"ledger_file"`
}
func paths(root,engagement string)(ledger,lock string){
 sum:=sha256.Sum256([]byte(engagement))
 stem:=".bunnymind-quota-"+hex.EncodeToString(sum[:12])
 return filepath.Join(root,stem+".json"),filepath.Join(root,stem+".lock")
}
// Reserve reserves the *maximum* intended number of network calls before any
// Python subprocess starts. It never refunds unspent requests automatically:
// a failed process or crash must not silently replenish a shared budget.
func Reserve(ctx context.Context,root,engagement string,amount,maximum int)(Receipt,error){
 if strings.TrimSpace(root)==""||len(root)>2048||engagement==""||len(engagement)>128||
  amount<1||amount>maximum||maximum<1||maximum>100000{
  return Receipt{},errors.New("invalid shared Python proof request reservation")
 }
 if err:=os.MkdirAll(root,0700);err!=nil{return Receipt{},err}
 ledgerPath,lockPath:=paths(root,engagement)
 deadline:=time.Now().Add(5*time.Second)
 var lock *os.File
 for{
  var err error
  lock,err=os.OpenFile(lockPath,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
  if err==nil{break}
  if !os.IsExist(err){return Receipt{},err}
  if time.Now().After(deadline){return Receipt{},errors.New("another proof process holds the engagement budget lock")}
  select{
  case <-ctx.Done():return Receipt{},ctx.Err()
  case <-time.After(40*time.Millisecond):
  }
 }
 defer func(){lock.Close();_ = os.Remove(lockPath)}()
 ledger:=Ledger{Version:1,EngagementID:engagement}
 data,err:=os.ReadFile(ledgerPath)
 if err!=nil&&!os.IsNotExist(err){return Receipt{},err}
 if err==nil{
  if len(data)>4096{return Receipt{},errors.New("shared proof request ledger exceeded maximum size")}
  if json.Unmarshal(data,&ledger)!=nil||ledger.Version!=1||
   ledger.EngagementID!=engagement||ledger.RequestsReserved<0{
   return Receipt{},errors.New("shared proof request ledger is corrupt; refusing new traffic")
  }
 }
 if ledger.RequestsReserved>maximum-amount{
  return Receipt{},fmt.Errorf("engagement request budget exhausted: already reserved %d of %d",ledger.RequestsReserved,maximum)
 }
 receipt:=Receipt{Before:ledger.RequestsReserved,Reserved:amount,
  Total:ledger.RequestsReserved+amount,Maximum:maximum,LedgerFile:filepath.Base(ledgerPath)}
 ledger.RequestsReserved=receipt.Total
 ledger.UpdatedAt=time.Now().UTC().Format(time.RFC3339Nano)
 encoded,err:=json.MarshalIndent(ledger,"","  ")
 if err!=nil{return Receipt{},err}
 fd,err:=os.CreateTemp(root,".bunnymind-quota-temp-*")
 if err!=nil{return Receipt{},err}
 temp:=fd.Name()
 defer os.Remove(temp)
 if err:=fd.Chmod(0600);err!=nil{fd.Close();return Receipt{},err}
 if _,err:=fd.Write(encoded);err!=nil{fd.Close();return Receipt{},err}
 if err:=fd.Sync();err!=nil{fd.Close();return Receipt{},err}
 if err:=fd.Close();err!=nil{return Receipt{},err}
 if err:=os.Rename(temp,ledgerPath);err!=nil{return Receipt{},err}
 return receipt,nil
}
func Read(root,engagement string)(Ledger,error){
 if engagement==""{return Ledger{},errors.New("engagement required")}
 path,_:=paths(root,engagement)
 fd,err:=os.Open(path)
 if err!=nil{return Ledger{},err}
 defer fd.Close()
 raw,err:=io.ReadAll(io.LimitReader(fd,4097))
 if err!=nil||len(raw)>4096{return Ledger{},errors.New("shared budget ledger invalid or oversized")}
 var ledger Ledger
 if json.Unmarshal(raw,&ledger)!=nil||ledger.Version!=1||ledger.EngagementID!=engagement{
  return Ledger{},errors.New("shared budget ledger was modified unexpectedly")
 }
 return ledger,nil
}
