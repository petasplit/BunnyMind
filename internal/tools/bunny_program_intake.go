package tools

import (
 "context"
 "encoding/json"

 "github.com/enowdev/antares/internal/bunnyprogram"
 "github.com/enowdev/antares/internal/config"
)

// programIntakeTool reads public program rules (not an application endpoint).
// It is intentionally separate from the BunnyGuard active assessment gate;
// its destination is hard-coded to public YesWeHack program pages.
type programIntakeTool struct{}
func (programIntakeTool) Name()string{return "program_intake"}
func (programIntakeTool) Description()string {
 return "Fetch a public YesWeHack bug bounty program URL and extract scope "+
  "entries, out-of-scope exclusions, testing precautions and source hashes. "+
  "This is read-only policy discovery, NOT authorization to test every asset. "+
  "Only HTTPS yeswehack.com/programs/<slug> is accepted. No redirects, cookies "+
  "or arbitrary external sites."
}
func (programIntakeTool) Schema()map[string]any{
 return schema(map[string]any{
  "url":prop("string","Exact public YesWeHack program page URL."),
 },"url")
}
func (programIntakeTool) UntrustedOutput()bool{return true}
func (programIntakeTool) RequiresApproval()bool{return false}
func (programIntakeTool) Execute(ctx context.Context,in Input)Result{
 var args struct{URL string `json:"url"`}
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid program intake arguments: %v",err)}
 if _,err:=bunnyprogram.AllowedProgramURL(args.URL);err!=nil{return Errorf("invalid public program page: %v",err)}
 if in.Emit!=nil{in.Emit(Progress{Tool:"program_intake",Message:"Retrieving public bug bounty program rules"})}
 snapshot,err:=bunnyprogram.Fetch(ctx,args.URL)
 if err!=nil{return Errorf("public program retrieval unavailable: %v",err)}
 if in.Emit!=nil{in.Emit(Progress{Tool:"program_intake",Message:"Extracted scope, exclusions and testing precautions"})}
 if proposed,e:=bunnyprogram.Draft(snapshot);e==nil{
  if filename,e:=bunnyprogram.SaveProposal(config.Path("bunnymind","program-proposals"),proposed);e==nil{
   snapshot.ScopeProposalFile=filename
   snapshot.Notes=append(snapshot.Notes,"An inactive scope proposal was saved. Review and narrow it before activation; this tool never applies it.")
  }else{
   snapshot.Notes=append(snapshot.Notes,"Scope proposal could not be saved; inspect the verified scope entries.")
  }
 }
 raw,err:=json.MarshalIndent(snapshot,"","  ")
 if err!=nil{return Errorf("cannot serialize public program rules")}
 return Text(string(raw))
}
