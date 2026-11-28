package tools

import (
 "context"
 "encoding/json"

 "github.com/enowdev/antares/internal/bunnypassive"
)

// passiveCTTool reads public CA certificate logs; it cannot crawl or probe
// any discovered domain. It is a metadata-only research step.
type passiveCTTool struct{}
func (passiveCTTool) Name()string{return "passive_subdomains"}
func (passiveCTTool) Description()string{
 return "Query public certificate transparency records for a registrable "+
  "domain after public program intake. Does not connect to any target or "+
  "assume that discovered hosts are in scope. Results are bounded and "+
  "clearly marked incomplete if the CT provider exceeds the response cap."
}
func (passiveCTTool) Schema()map[string]any{
 return schema(map[string]any{"domain":prop("string","Registrable DNS domain explicitly supported by the program scope.")},"domain")
}
func (passiveCTTool) UntrustedOutput()bool{return true}
func (passiveCTTool) RequiresApproval()bool{return false}
func (passiveCTTool) Execute(ctx context.Context,in Input)Result{
 var args struct{Domain string `json:"domain"`}
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid passive CT args: %v",err)}
 if _,err:=bunnypassive.ValidDomain(args.Domain);err!=nil{return Errorf("invalid passive CT domain: %v",err)}
 if in.Emit!=nil{in.Emit(Progress{Tool:"passive_subdomains",Message:"Querying public certificate transparency"})}
 output,err:=bunnypassive.Query(ctx,args.Domain)
 if err!=nil{return Errorf("public CT discovery unavailable: %v",err)}
 raw,err:=json.MarshalIndent(output,"","  ")
 if err!=nil{return Errorf("CT observations could not be serialized")}
 return Text(string(raw))
}
