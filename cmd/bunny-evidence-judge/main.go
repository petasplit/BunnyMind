// bunny-judge is a second, offline evidence reviewer. It never generates
// exploits, contacts targets or asserts impact from a marker observation.
package main

import (
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnyjudge"
)

func run()error{
 folder:=flag.String("run","","Existing sealed Python evidence run directory")
 flag.Parse()
 if *folder==""||flag.NArg()!=0{return errors.New("usage: BunnyMind-evidence-judge.exe --run <sealed-run-directory>")}
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return fmt.Errorf("cannot access local evidence key: %w",err)}
 report,err:=bunnyjudge.JudgeRun(*folder,key)
 if err!=nil{return fmt.Errorf("independent offline evidence review failed: %w",err)}
 raw,err:=json.MarshalIndent(report,"","  ")
 if err!=nil{return err}
 fmt.Println(string(raw))
 return nil
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
