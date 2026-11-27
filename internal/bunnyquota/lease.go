package bunnyquota

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "time"
)

// ExecutionLease permits only one active Python proof network execution for
// one engagement/output root. This prevents simultaneous runner processes
// from interleaving request timing and violating an intended rate envelope.
func ExecutionLease(ctx context.Context,root,engagement string)(func(),error){
 if root==""||engagement==""||len(root)>2048||len(engagement)>128{
  return nil,errors.New("invalid Python execution lease context")
 }
 if err:=os.MkdirAll(root,0700);err!=nil{return nil,err}
 digest:=sha256.Sum256([]byte(engagement))
 file:=filepath.Join(root,".bunnymind-running-"+hex.EncodeToString(digest[:12])+".lock")
 deadline:=time.Now().Add(5*time.Second)
 for{
  fd,err:=os.OpenFile(file,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
  if err==nil{
   _=fd.Close()
   var once sync.Once
   return func(){once.Do(func(){_ = os.Remove(file)})},nil
  }
  if !os.IsExist(err){return nil,err}
  if time.Now().After(deadline){
   return nil,errors.New("a Python proof process already owns this engagement's execution lease")
  }
  select{
  case <-ctx.Done():return nil,ctx.Err()
  case <-time.After(40*time.Millisecond):
  }
 }
}
