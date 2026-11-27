package agent

import (
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/config"
 "github.com/enowdev/antares/internal/store"
 "github.com/enowdev/antares/internal/tools"
)
func TestStructuredEngagementActuallyRunsScopedReadBeforeModel(t *testing.T){
 requests:=0
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  requests++
  if r.Method!="GET"||r.URL.Path!="/health"{
   t.Errorf("unexpected request %s %s",r.Method,r.URL.Path)
  }
  w.Header().Set("Content-Type","text/plain")
  _,_=w.Write([]byte("synthetic local application, nothing private"))
 }))
 defer server.Close()
 policyPath:=filepath.Join(t.TempDir(),"manifest.json")
 b,err:=json.Marshal(bunnyguard.Policy{
  EngagementID:"local_tool_first_fixture",
  AllowedOrigins:[]string{server.URL},AllowedMethods:[]string{"GET"},
  MaxNetworkCalls:2,
 })
 if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(policyPath,b,0600);err!=nil{t.Fatal(err)}
 t.Setenv(bunnyguard.EnvPolicy,policyPath)
 ctx:=context.Background()
 db,err:=store.Open(ctx,"memory","",1,5000,false)
 if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = db.Close()})
 sess:=&store.Session{ID:"tool_first_lab",Workspace:t.TempDir(),Meta:store.Meta{}}
 if err:=db.CreateSession(ctx,sess);err!=nil{t.Fatal(err)}
 cfg:=config.Default()
 cfg.Tools.ApprovalMode="prompt" // scoped read is approved by validated manifest
 a:=New(cfg,db,tools.Default(),nil,nil)
 reader,ok:=tools.Default().Get("scoped_read")
 if !ok{t.Fatal("restricted HTTP tool not registered")}
 var events []Event
 emit:=func(e Event)error{events=append(events,e);return nil}
 req:=Request{SessionID:sess.ID,Role:"security",
  Message:"Description: local authorized synthetic site\nTarget: "+server.URL+"/health\nScope: "+server.URL,
 }
 history,used,err:=a.autoKickoff(ctx,req,sess,map[string]tools.Tool{"scoped_read":reader},"test-model",emit)
 if err!=nil{t.Fatal(err)}
 if used!=1||requests!=1{t.Fatalf("expected 1 real request: tools=%d requests=%d",used,requests)}
 if len(history)!=2||len(history[0].ToolCalls)!=1||
  history[0].ToolCalls[0].Name!="scoped_read"||
  history[1].Role!="tool"||!strings.Contains(history[1].Content,`"status": 200`){
  t.Fatalf("model transcript missing real tool call/result: %+v",history)
 }
 seenCall,seenResult,seenText:=false,false,false
 for _,e:=range events{
  switch e.Type{
  case EventToolCall:seenCall=true
  case EventToolResult:seenResult=true
  case EventText:seenText=true
  }
 }
 if !seenCall||!seenResult||seenText{t.Fatalf("expected tool activity with no preamble: %+v",events)}
 // A genuine automatic request consumes the normal BunnyGuard call budget.
 g,err:=bunnyguard.New(policyPath)
 if err!=nil{t.Fatal(err)}
 if g.Manifest().EngagementID!="local_tool_first_fixture"{t.Fatal("wrong policy")}
 if !strings.Contains(history[1].Content,"synthetic local application"){
  t.Fatal("scoped GET did not actually read controlled fixture")
 }
}
func TestStructuredEngagementWithoutPolicyNeverCallsNetwork(t *testing.T){
 t.Setenv(bunnyguard.EnvPolicy,"")
 var events []Event
 a:=&Agent{}
 req:=Request{Message:"Target: http://127.0.0.1:8000\nScope: 127.0.0.1"}
 history,count,err:=a.autoKickoff(context.Background(),req,&store.Session{ID:"none"},nil,"model",func(e Event)error{
  events=append(events,e);return nil
 })
 if err!=nil||count!=0||len(history)!=0{t.Fatalf("unapproved kickoff: %d %+v %v",count,history,err)}
 if len(events)!=1||events[0].Type!=EventNotice||!strings.Contains(events[0].Message,"manifest"){
  t.Fatalf("missing policy must report a factual blocked status: %+v",events)
 }
}
