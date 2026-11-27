// bunnybench scores declared vulnerability claims against instrumented lab
// evidence. It never sends a network request or executes an AI model.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/enowdev/antares/internal/bunnybench"
)
func main(){
	in:=flag.String("input","","JSON study file (manifest and one or more trials)")
	output:=flag.String("output","","Optional JSON result file; defaults to stdout")
	flag.Parse()
	if *in==""{fmt.Fprintln(os.Stderr,"usage: bunnybench -input study.json [-output score.json]");os.Exit(2)}
	data,err:=os.ReadFile(*in)
	if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
	var study bunnybench.Study
	if err=json.Unmarshal(data,&study);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
	result,err:=bunnybench.ScoreStudy(study)
	if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
	b,err:=json.MarshalIndent(result,"","  ")
	if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
	b=append(b,'\n')
	if *output!=""{
		if err=os.WriteFile(*output,b,0600);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
	}else{fmt.Print(string(b))}
}
