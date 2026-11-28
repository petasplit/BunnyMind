package agent

import (
 "context"
 "encoding/json"
 "net/url"
 "os"
 "regexp"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyprogram"
 "github.com/enowdev/antares/internal/bunnypassive"
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
// scopeDocumentationReply handles an authorized-research request that has
// supplied a bug-bounty PROGRAM page but no actual testable asset. A program
// listing does not grant permission to probe the platform itself, and a model
// refusal or a printed JSON pseudo-tool-call should not be the user experience.
// This branch sends no network request and never invents an in-scope host.
func scopeDocumentationReply(req Request) string {
 if req.Quiet||req.Depth!=0||!securityAssessmentRequest(req){return ""}
 lower:=strings.ToLower(req.Message)
 if !strings.Contains(lower,"yeswehack.com/programs/") && !(strings.Contains(lower,"yeswehack") && strings.Contains(lower,"bug bounty")){return ""}
 // A separate Target/Scope pair can already use the approved guard path.
 if brief,ok:=parseAutoEngagement(req.Message);ok&&brief.URL!=""{return ""}
 return "I can help with this authorized bug-bounty program. The YesWeHack link is the program description, not a confirmed in-scope testing endpoint. To start an actual assessment, configure BunnyGuard (ANTARES_BUNNY_GUARD_POLICY) with the program's allowed origins and methods, and provide an exact in-scope target URL in a Target: line plus a matching Scope: line. Once those match the approved manifest, BunnyMind can begin with a bounded scoped_read and preserve the evidence. No external scan has been started, and I will not mistake the YesWeHack platform itself for an authorized target."
}

var publicProgramRE=regexp.MustCompile(`https://yeswehack[.]com/programs/[A-Za-z0-9_-]{2,111}`)
func publicProgramURL(message string) string {
 for _,candidate:=range publicProgramRE.FindAllString(message,8){
  if valid,err:=bunnyprogram.AllowedProgramURL(candidate);err==nil{return valid}
 }
 return ""
}

// executeKickoff records a real tool call and response before model narration.
// The result goes into persisted history and the same UI tool timeline.
func (a *Agent) executeKickoff(ctx context.Context,req Request,sess *store.Session,
 byName map[string]tools.Tool,modelName string,emit Emit,name string,args map[string]any,
 history []llm.Message)([]llm.Message,bool,string,error) {
 if _,ok:=byName[name];!ok{return history,false,"",nil}
 serialized,err:=json.Marshal(args)
 if err!=nil{return history,false,"",err}
 call:=llm.ToolCall{ID:newID("tool"),Name:name,Arguments:string(serialized)}
 if err:=emit(Event{Type:EventNotice,Message:securityActionStatus(name)});err!=nil{return history,false,"",err}
 history=append(history,llm.Message{Role:llm.RoleAssistant,ToolCalls:[]llm.ToolCall{call}})
 if !req.Quiet{a.persistAssistant(ctx,sess.ID,modelName,&llm.Response{ToolCalls:[]llm.ToolCall{call}})}
 results:=a.executeTools(ctx,[]llm.ToolCall{call},byName,req,sess,emit)
 for _,out:=range results{
  if !req.Quiet {
   if err:=a.db.AppendMessage(ctx,&store.Message{
    ID:newID("msg"),SessionID:sess.ID,Role:store.RoleTool,
    Content:out.message.Content,ToolCallID:out.message.ToolCallID,ToolName:out.message.Name,
    Meta:store.Meta{"is_error":out.isError},
   });err!=nil{return history,true,"",err}
  }
 }
 history=appendTurnMessages(history,results,"",nil)
 raw:=""
 if len(results)>0&&!results[0].isError{raw=results[0].message.Content}
 return history,true,raw,nil
}

// autoKickoff selects the restricted read tool deterministically: the
// language model cannot delay initial action with a speculative plan.
// All existing GateFromEnv, tool budget, audit and network controls still run.
func (a *Agent) autoKickoff(ctx context.Context,req Request,sess *store.Session,
 byName map[string]tools.Tool,modelName string,emit Emit)([]llm.Message,int,error) {
 if req.Quiet||req.Depth!=0||isSubordinateRun(req){return nil,0,nil}
 history:=[]llm.Message{}
 count:=0
 if program:=publicProgramURL(req.Message);program!="" {
  next,ran,raw,err:=a.executeKickoff(ctx,req,sess,byName,modelName,emit,
   "program_intake",map[string]any{"url":program},history)
  if err!=nil{return next,count,err}
  history=next
  if ran{count++}
  // Public certificate logs are metadata; they do not contact any target.
  // Derive at most one registrable search root from a *verified* program
  // scope row, not an arbitrary URL written by the model.
  if raw!="" && strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))=="" {
   var snapshot bunnyprogram.Snapshot
   if json.Unmarshal([]byte(raw),&snapshot)==nil{
    roots:=bunnypassive.RootsForProgram(snapshot.ScopeEntries)
    if len(roots)>0{
     root:=roots[0]
     for _,candidate:=range roots {
      if candidate=="doctolib.fr"{root=candidate;break}
     }
     after,observed,_,err:=a.executeKickoff(ctx,req,sess,byName,modelName,emit,
      "passive_subdomains",map[string]any{"domain":root},history)
     if err!=nil{return after,count,err}
     history=after
     if observed{count++}
    }
   }
  }
 }
 brief,notice:=authorizedAutoEngagement(req.Message,strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy)))
 if notice!=""{
  if err:=emit(Event{Type:EventNotice,Message:notice});err!=nil{return history,count,err}
  return history,count,nil
 }
 if brief.URL==""{return history,count,nil}
 if _,ok:=byName["scoped_read"];!ok {
  if err:=emit(Event{Type:EventNotice,Message:"Engagement paused: scoped_read is unavailable"});err!=nil{return history,count,err}
  return history,count,nil
 }
 next,ran,_,err:=a.executeKickoff(ctx,req,sess,byName,modelName,emit,
  "scoped_read",map[string]any{"url":brief.URL,"method":"GET","preview_bytes":2048},history)
 if err!=nil{return next,count,err}
 if ran{count++}
 return next,count,nil
}
