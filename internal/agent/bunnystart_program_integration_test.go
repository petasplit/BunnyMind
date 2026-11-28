package agent

import (
 "context"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyprogram"
 "github.com/enowdev/antares/internal/config"
 "github.com/enowdev/antares/internal/store"
 "github.com/enowdev/antares/internal/tools"
)

type fakeProgramTool struct{
 name string
 calls *[]string
 output string
}
func (f fakeProgramTool) Name()string{return f.name}
func (f fakeProgramTool) Description()string{return "controlled test stub"}
func (f fakeProgramTool) Schema()map[string]any{return map[string]any{"type":"object"}}
func (f fakeProgramTool) RequiresApproval()bool{return false}
func (f fakeProgramTool) Execute(_ context.Context,in tools.Input)tools.Result{
 *f.calls=append(*f.calls,f.name+":"+string(in.Args))
 return tools.Text(f.output)
}
func programTestAgent(t *testing.T)(*Agent,*store.Session){
 t.Helper()
 db,err:=store.Open(context.Background(),"memory","",1,5000,false)
 if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = db.Close()})
 sess:=&store.Session{ID:"public_program_lab",Workspace:t.TempDir(),Meta:store.Meta{}}
 if err:=db.CreateSession(context.Background(),sess);err!=nil{t.Fatal(err)}
 cfg:=config.Default()
 cfg.Tools.ApprovalMode="auto"
 return New(cfg,db,tools.Default(),nil,nil),sess
}
func TestPublicProgramStartsActualPolicyAndPassiveToolsBeforeModel(t *testing.T){
 t.Setenv(bunnyguard.EnvPolicy,"")
 agent,sess:=programTestAgent(t)
 snapshot:=bunnyprogram.Snapshot{
  ProgramURL:"https://yeswehack.com/programs/test-program",
  PageSHA256:strings.Repeat("a",64),ScopeEntries:[]string{"www.doctolib.(fr|de|it) Web application"},
  ProposedExactWebOrigins:[]string{"https://www.doctolib.fr"},
 }
 raw,_:=json.Marshal(snapshot)
 calls:=[]string{}
 names:=map[string]tools.Tool{}
 for key,out:=range map[string]string{"program_intake":string(raw),"passive_subdomains":`{"status":"public_ct_observations"}`}{
  names[key]=fakeProgramTool{name:key,calls:&calls,output:out}
 }
 var events []Event
 emit:=func(e Event)error{events=append(events,e);return nil}
 history,count,err:=agent.autoKickoff(context.Background(),Request{Role:"security",
  Message:"Bug bounty: https://yeswehack.com/programs/test-program"},sess,names,"fixture-model",emit)
 if err!=nil{t.Fatal(err)}
 if count!=2||len(calls)!=2||!strings.HasPrefix(calls[0],"program_intake:")||
  !strings.HasPrefix(calls[1],"passive_subdomains:")||
  !strings.Contains(calls[1],"doctolib.fr"){
  t.Fatalf("tool-first passive kickoff did not occur: count %d calls %#v",count,calls)
 }
 if len(history)!=4{t.Fatalf("missing tool events/results in agent history: %#v",history)}
 for _,e:=range events{if e.Type==EventText||e.Type==EventReasoning{t.Fatal("model narration was emitted before tools")}}
}
func TestPublicProgramCanCrawlOnlyReviewedScopeIntersection(t *testing.T){
 agent,sess:=programTestAgent(t)
 policyFile:=filepath.Join(t.TempDir(),"guard.json")
 data,_:=json.Marshal(bunnyguard.Policy{EngagementID:"program_fixture",AllowedOrigins:[]string{
  "https://www.doctolib.fr","https://community.doctolib.fr",
 },AllowedMethods:[]string{"GET"},MaxNetworkCalls:24})
 if err:=os.WriteFile(policyFile,data,0600);err!=nil{t.Fatal(err)}
 t.Setenv(bunnyguard.EnvPolicy,policyFile)
 snapshot:=bunnyprogram.Snapshot{
  ProgramURL:"https://yeswehack.com/programs/test-program",
  PageSHA256:strings.Repeat("a",64),
  ProposedExactWebOrigins:[]string{"https://www.doctolib.fr","https://community.doctolib.fr"},
  OutOfScope:[]string{"community.doctolib.com | .fr | .de | .it"},
 }
 raw,_:=json.Marshal(snapshot)
 calls:=[]string{}
 names:=map[string]tools.Tool{}
 for key,out:=range map[string]string{"program_intake":string(raw),"scoped_crawl":`{"requests_used":2}`}{
  names[key]=fakeProgramTool{name:key,calls:&calls,output:out}
 }
 var notices []string
 history,count,err:=agent.autoKickoff(context.Background(),Request{Role:"security",
  Message:"Audit https://yeswehack.com/programs/test-program"},sess,names,"fixture-model",func(e Event)error{
  if e.Type==EventNotice{notices=append(notices,e.Message)}
  return nil
 })
 if err!=nil{t.Fatal(err)}
 if count!=2||len(history)!=4||len(calls)!=2||!strings.HasPrefix(calls[1],"scoped_crawl:")||
  !strings.Contains(calls[1],"www.doctolib.fr")||strings.Contains(calls[1],"community.doctolib.fr"){
  t.Fatalf("auto crawler did not respect reviewed scope: %#v %#v",history,calls)
 }
}
