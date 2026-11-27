// bunny-browser-auth-demo exercises a real local Chromium session with two
// disposable browser test personas, in-process OTP and cookie isolation.
package main

import (
 "context"
 "encoding/json"
 "fmt"
 "os"
 "time"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
)
func main(){
 ctx,cancel:=context.WithTimeout(context.Background(),2*time.Minute)
 defer cancel()
 result,err:=bunnybrowserflow.RunLab(ctx)
 if err!=nil{
  fmt.Fprintln(os.Stderr,"BunnyMind local browser fixture failed:",err)
  os.Exit(1)
 }
 out,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{os.Exit(1)}
 fmt.Println(string(out))
}
