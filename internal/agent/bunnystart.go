package agent

import (
 "context"
 "encoding/json"
 "net/url"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/llm"
 "github.com/enowdev/antares/internal/store"
 "github.com/enowdev/antares/internal/tools"
)

// autoEngagement is a deliberately conservative user-intent recognizer.
// It does not infer scope or permission from a URL alone. A literal target,
// explicit scope declaration, and separately configured BunnyGuard manifest
// are ALL required before the runtime performs even one read-only request.
type autoEngagement struct{
 URL string
 Origin string
}
func readLabeledLine(raw string)(string,string){
 line:=strings.TrimSpace(raw)
 line=strings.TrimLeft(line,"-* \t")
 line=strings.ReplaceAll(line,"**","")
 at:=strings.IndexAny(line,":=")
 if at<0{return "",""}
 key:=strings.ToLower(strings.TrimSpace(line[:at]))
 val:=strings.TrimSpace(line[at+1:])
 return key,val
}
func matchScope(scope string,u *url.URL)bool{
 scope=strings.ToLower(scope)
 host:=strings.ToLower(u.Hostname())
 origin:=strings.ToLower(u.Scheme+"://"+u.Host)
 if strings.TrimSpace(scope)=="target only"||strings.TrimSpace(scope)=="this target only"{
  return true
 }
 // The operator manifest remains authoritative; a nonempty, explicit scope
 // line naming the target must still be present. Reject general claims such
 // as "all assets" or mere program names.
 for _,field:=range strings.FieldsFunc(scope,func(r rune)bool{
  return r==','||r==';'||r==' '||r=='\t'||r=='['||r==']'||r=='('||r==')'
 }){
  field=strings.Trim(field,"./")
  if field==host||field==strings.TrimPrefix(origin,"https://")||
   field==strings.TrimPrefix(origin,"http://")||field==origin{
   return true
  }
 }
 return false
}
func parseAutoEngagement(message string)(autoEngagement,bool){
 if len(message)>65536{return autoEngagement{},false}
 var target,scope string
 for _,raw:=range strings.Split(message,"\n"){
  key,value:=readLabeledLine(raw)
  switch key{
  case "target","target url","url":
   if target!=""{return autoEngagement{},false}
   target=strings.TrimRight(value,",;")
  case "scope","in-scope","in scope","allowed origins":
   if scope!=""{return autoEngagement{},false}
   scope=value
  }
 }
 if target==""||scope==""{return autoEngagement{},false}
 if strings.ContainsAny(target," \t\r\n") {return autoEngagement{},false}
 u,err:=url.Parse(target)
 if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||
  (u.Scheme!="http"&&u.Scheme!="https")||u.Hostname()==""||
  u.RawQuery!=""||u.Fragment!=""{
  return autoEngagement{},false
 }
 if !matchScope(scope,u){return autoEngagement{},false}
 origin:=strings.ToLower(u.Scheme+"://"+u.Host)
 return autoEngagement{URL:u.String(),Origin:origin},true
}
func authorizedAutoEngagement(message,manifestPath string)(autoEngagement,string){
 brief,ok:=parseAutoEngagement(message)
 if !ok{return autoEngagement{},""}
 if manifestPath==""{
  return autoEngagement{},"Engagement paused: approved BunnyGuard scope manifest not configured"
 }
 guard,err:=bunnyguard.New(manifestPath)
 if err!=nil{return autoEngagement{},"Engagement paused: approved scope policy unavailable"}
 p:=guard.Manifest()
 approved:=false
 for _,allowed:=range p.AllowedOrigins{
  u,err:=url.Parse(allowed)
  if err==nil&&u!=nil&&strings.ToLower(u.Scheme+"://"+u.Host)==brief.Origin{
   approved=true;break
  }
 }
 if !approved{return autoEngagement{},"Engagement paused: target outside approved origin"}
 getAllowed:=len(p.AllowedMethods)==0
 for _,method:=range p.AllowedMethods{if strings.EqualFold(strings.TrimSpace(method),"GET"){getAllowed=true}}
 if !getAllowed{return autoEngagement{},"Engagement paused: read-only HTTP method not approved"}
 return brief,""
}
// autoKickoff selects the restricted read tool deterministically: the
// language model cannot delay initial action with a speculative plan.
// All existing GateFromEnv, tool budget, audit and network controls still run.
func (a *Agent) autoKickoff(ctx context.Context,req Request,sess *store.Session,byName map[string]tools.Tool,modelName string,emit Emit)([]llm.Message,int,error){
 if req.Quiet||req.Depth!=0||isSubordinateRun(req){return nil,0,nil}
 brief,notice:=authorizedAutoEngagement(req.Message,strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy)))
 if notice!="" {
  if err:=emit(Event{Type:EventNotice,Message:notice});err!=nil{return nil,0,err}
  return nil,0,nil
 }
 if brief.URL==""{return nil,0,nil}
 if _,ok:=byName["scoped_read"];!ok{
  if err:=emit(Event{Type:EventNotice,Message:"Engagement paused: restricted HTTP tool is unavailable"});err!=nil{return nil,0,err}
  return nil,0,nil
 }
 args,_:=json.Marshal(map[string]any{"url":brief.URL,"method":"GET","preview_bytes":2048})
 call:=llm.ToolCall{ID:newID("tool"),Name:"scoped_read",Arguments:string(args)}
 if err:=emit(Event{Type:EventNotice,Message:"Checking approved scope"});err!=nil{return nil,0,err}
 history:=[]llm.Message{{Role:llm.RoleAssistant,ToolCalls:[]llm.ToolCall{call}}}
 if !req.Quiet{
  a.persistAssistant(ctx,sess.ID,modelName,&llm.Response{ToolCalls:[]llm.ToolCall{call}})
 }
 results:=a.executeTools(ctx,[]llm.ToolCall{call},byName,req,sess,emit)
 for _,out:=range results{
  if !req.Quiet{
   if err:=a.db.AppendMessage(ctx,&store.Message{
    ID:newID("msg"),SessionID:sess.ID,Role:store.RoleTool,
    Content:out.message.Content,ToolCallID:out.message.ToolCallID,ToolName:out.message.Name,
    Meta:store.Meta{"is_error":out.isError},
   });err!=nil{return nil,1,err}
  }
 }
 history=appendTurnMessages(history,results,"",nil)
 if len(results)>0&&results[0].isError{
  if err:=emit(Event{Type:EventNotice,Message:"Initial inspection blocked"});err!=nil{return history,1,err}
 }else{
  if err:=emit(Event{Type:EventNotice,Message:"Initial inspection recorded; continuing investigation"});err!=nil{return history,1,err}
 }
 return history,1,nil
}
