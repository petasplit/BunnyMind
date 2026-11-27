package agent

import (
 "context"
 "encoding/json"
 "errors"
 "net/url"
 "os"
 "regexp"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/llm"
 "github.com/enowdev/antares/internal/store"
 "github.com/enowdev/antares/internal/tools"
)
// autoEngagement is an exact, already-authorized target URL. It is never
// populated solely by a model assertion or an unrelated URL in a document.
type autoEngagement struct{URL string}
var targetLine=regexp.MustCompile(`(?i)^\s*(target|url|website)\s*:\s*(https?://\S+)\s*$`)
var scopeLine=regexp.MustCompile(`(?i)^\s*(scope|in[- ]scope|allowed origins?)\s*:\s*(.+)$`)
func validAutoURL(raw string)(*url.URL,error){
 raw=strings.TrimRight(strings.TrimSpace(raw),",.;)]}")
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||
 (u.Scheme!="https"&&u.Scheme!="http")||u.Host==""||u.Hostname()==""||
 len(raw)>2048||u.Fragment!=""{
  return nil,errors.New("target URL must be a complete HTTP(S) URL without credentials")
 }
 return u,nil
}
// authorizedAutoEngagement requires BOTH an explicit Target: line and a
// matching explicit Scope: line, plus a validated operator manifest.
// Any mismatch or ambiguity fails closed. This parser intentionally cannot
// infer wildcard subdomains, scope from a brand name, or other assets.
func authorizedAutoEngagement(message,manifestPath string)(autoEngagement,error){
 if manifestPath==""{return autoEngagement{},errors.New("approved manifest missing")}
 if len(message)>32768{return autoEngagement{},errors.New("mission description too large")}
 guard,err:=bunnyguard.New(manifestPath)
 if err!=nil{return autoEngagement{},err}
 var target *url.URL
 explicitScope:=false
 targetCount:=0
 for _,line:=range strings.Split(message,"\n"){
  trimmed:=strings.TrimSpace(line)
  if m:=targetLine.FindStringSubmatch(trimmed);m!=nil{
   targetCount++
   if targetCount>1{return autoEngagement{},errors.New("multiple target lines require manual review")}
   target,err=validAutoURL(m[2]);if err!=nil{return autoEngagement{},err}
  }
 }
 if target==nil{return autoEngagement{},errors.New("explicit target URL line not supplied")}
 origin:=strings.ToLower(target.Scheme+"://"+target.Host)
 approved:=false
 for _,item:=range guard.Manifest().AllowedOrigins{
  u,e:=validAutoURL(item)
  if e==nil&&strings.ToLower(u.Scheme+"://"+u.Host)==origin {approved=true}
 }
 if !approved{return autoEngagement{},errors.New("target is outside approved engagement origins")}
 for _,line:=range strings.Split(message,"\n"){
  trimmed:=strings.TrimSpace(line)
  if m:=scopeLine.FindStringSubmatch(trimmed);m!=nil{
   // An explicit scheme+host (with optional path) is required. Parse
   // comma/space-separated entries individually; do not treat arbitrary
   // prose or a wildcard as proof that an origin is in scope.
   for _,tok:=range strings.FieldsFunc(m[2],func(r rune)bool{return r==' '||r==','||r=='\t'}){
    scoped,e:=validAutoURL(tok)
    if e==nil&&strings.ToLower(scoped.Scheme+"://"+scoped.Host)==origin{
     explicitScope=true
    }
   }
  }
 }
 if !explicitScope{return autoEngagement{},errors.New("target not expressly listed on scope line")}
 return autoEngagement{URL:target.String()},nil
}
// autoKickoff executes the first bounded, manifest-approved GET without
// waiting for a model-generated introduction. Scope/approval and DNS/IP
// protections remain inside executeTools and the scoped HTTP transport.
func (a *Agent) autoKickoff(
 ctx context.Context,req Request,sess *store.Session,
 byName map[string]tools.Tool,modelName string,emit Emit,
)([]llm.Message,int,error){
 if req.Quiet||req.Depth!=0||req.Role!="security"{return nil,0,nil}
 if _,ok:=byName["scoped_read"];!ok{return nil,0,nil}
 path:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 parsed,err:=authorizedAutoEngagement(req.Message,path)
 if err!=nil{return nil,0,nil}
 args,err:=json.Marshal(map[string]any{"url":parsed.URL,"method":"GET","preview_bytes":0})
 if err!=nil{return nil,0,err}
 call:=llm.ToolCall{ID:newID("kickoff"),Name:"scoped_read",Arguments:string(args)}
 if err:=ctx.Err();err!=nil{return nil,0,err}
 results:=a.executeTools(ctx,[]llm.ToolCall{call},byName,req,sess,emit)
 // The tool event is a real tool execution, including denials and failures,
 // not a marketing progress claim. Persist all tool calls/results in order.
 assistant:=llm.Message{Role:llm.RoleAssistant,ToolCalls:[]llm.ToolCall{call}}
 if !req.Quiet {
  a.persistAssistant(ctx,sess.ID,modelName,&llm.Response{ToolCalls:[]llm.ToolCall{call}})
 }
 history:=[]llm.Message{assistant}
 for _,result:=range results{
  history=append(history,result.message)
  if !req.Quiet{
   if err:=a.db.AppendMessage(ctx,&store.Message{
    ID:newID("msg"),SessionID:sess.ID,Role:store.RoleTool,
    Content:result.message.Content,ToolCallID:result.message.ToolCallID,
    ToolName:result.message.Name,Meta:store.Meta{"is_error":result.isError},
   });err!=nil{
    return nil,0,err
   }
  }
 }
 return history,1,nil
}
