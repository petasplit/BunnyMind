package bunnyquota

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "strings"
)

// SharedRoot is stable across subprocesses, browser engines and sessions.
// The output destination is NOT used as a budget key: changing evidence
// directories must not reset an engagement's spending limit.
// BUNNY_SHARED_QUOTA_ROOT is a trusted operator setting, not a model argument.
func SharedRoot()(string,error){
 raw:=strings.TrimSpace(os.Getenv("BUNNY_SHARED_QUOTA_ROOT"))
 if raw!=""{
  if !filepath.IsAbs(raw)||len(raw)>1800{return "",errors.New("shared quota root must be an absolute private directory")}
  return filepath.Clean(raw),nil
 }
 config,err:=os.UserConfigDir()
 if err!=nil||config==""{return "",errors.New("OS configuration directory unavailable for persistent quota")}
 return filepath.Join(config,"BunnyMind","shared-network-quota"),nil
}
// ReserveShared charges the exact same persistent ledger regardless of which
// network-capable subsystem or output vault reserves the calls.
func ReserveShared(ctx context.Context,engagement string,calls,max int)(Receipt,error){
 root,err:=SharedRoot()
 if err!=nil{return Receipt{},err}
 return Reserve(ctx,root,engagement,calls,max)
}
// ExecutionLeaseShared serializes bulk crawler, browser and Python assessment
// engines for one engagement, preventing their in-flight bursts overlapping.
// Single GET calls are metered through ReserveShared at tool admission.
func ExecutionLeaseShared(ctx context.Context,engagement string)(func(),error){
 root,err:=SharedRoot()
 if err!=nil{return nil,err}
 return ExecutionLease(ctx,root,engagement)
}
