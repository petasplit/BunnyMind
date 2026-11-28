package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "time"

 "github.com/enowdev/antares/internal/bunnysandbox"
)
func run()error{
 profile:=flag.String("profile","","Operator-owned pinned-image sandbox JSON")
 evidence:=flag.String("evidence","","Private evidence vault directory")
 flag.Parse()
 if *profile==""||*evidence==""||flag.NArg()!=0{
  return errors.New("usage: BunnyMind-specialist-sandbox.exe --profile reviewed-offline-job.json --evidence Evidence")
 }
 cfg,err:=bunnysandbox.LoadSpec(*profile)
 if err!=nil{return err}
 ctx,cancel:=context.WithTimeout(context.Background(),time.Duration(cfg.TimeoutSeconds+10)*time.Second)
 defer cancel()
 result,err:=bunnysandbox.Run(ctx,cfg,*evidence)
 if err!=nil{return err}
 b,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return err}
 fmt.Println(string(b))
 return nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
