// Command bunny-program-intake retrieves a public bug bounty program's rules
// and produces an inactive reviewable scope proposal. It cannot scan targets.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "time"

 "github.com/enowdev/antares/internal/bunnyprogram"
 "github.com/enowdev/antares/internal/config"
)

func run()error{
 url:=flag.String("url","","Exact public YesWeHack program URL")
 output:=flag.String("out","","Where inactive scope proposals are written")
 flag.Parse()
 if *url==""||flag.NArg()!=0{return errors.New("usage: bunny-program-intake --url https://yeswehack.com/programs/<slug>")}
 dest:=*output
 if dest==""{dest=config.Path("bunnymind","program-proposals")}
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
 defer cancel()
 snapshot,err:=bunnyprogram.Fetch(ctx,*url)
 if err!=nil{return fmt.Errorf("program rules could not be verified: %w",err)}
 proposal,err:=bunnyprogram.Draft(snapshot)
 if err==nil{
  if file,err:=bunnyprogram.SaveProposal(dest,proposal);err==nil{snapshot.ScopeProposalFile=file}
 }
 encoded,err:=json.MarshalIndent(snapshot,"","  ")
 if err!=nil{return err}
 fmt.Println(string(encoded))
 return nil
}
func main(){
 if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
