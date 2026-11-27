package browser

import (
 "context"
 "encoding/json"
 "errors"
 "net/url"
 "strings"
 "time"
)
const maxScopedPopups=4
type popupSession struct{
 sessionID string
 targetID string
}
// popupInScope checks only the already-vetted external browser origins.
// The CONNECT proxy and per-target CDP Fetch gate independently enforce
// network permissions, including for windows opened by the IdP.
func popupInScope(raw string,allowed map[string]bool)bool{
 if raw=="about:blank"||raw==""{return true}
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||u.Scheme!="https"||
  u.Hostname()==""||(u.Port()!=""&&u.Port()!="443"){return false}
 return allowed["https://"+strings.ToLower(u.Hostname())]
}
// acceptPopup is called from an independent CDP event handler. Popups remain
// frozen until their Fetch request gate is installed, avoiding unfiltered
// navigation between Target creation and event handler attachment.
func (s *Session) acceptPopup(c *conn,g *externalGate,sessionID,targetID,targetURL string) {
 if sessionID==""||targetID==""||targetID==s.targetID{return}
 ctx,cancel:=context.WithTimeout(context.Background(),6*time.Second)
 defer cancel()
 if !popupInScope(targetURL,g.allowed) {
  _,_=c.send(ctx,"","Target.closeTarget",map[string]any{"targetId":targetID})
  return
 }
 s.popupMu.Lock()
 if len(s.popupSessions)>=maxScopedPopups{
  s.popupMu.Unlock()
  _,_=c.send(ctx,"","Target.closeTarget",map[string]any{"targetId":targetID})
  return
 }
 for _,other:=range s.popupSessions {
  if other.targetID==targetID{s.popupMu.Unlock();return}
 }
 s.popupMu.Unlock()
 // Fetch must be installed before the target is resumed.
 if _,err:=c.send(ctx,sessionID,"Fetch.enable",map[string]any{
  "patterns":[]map[string]string{{"urlPattern":"*","requestStage":"Request"}},
 });err!=nil{
  _,_=c.send(ctx,"","Target.closeTarget",map[string]any{"targetId":targetID})
  return
 }
 for _,method:=range []string{"Page.enable","Runtime.enable","Network.enable","DOM.enable"}{
  if _,err:=c.send(ctx,sessionID,method,nil);err!=nil{
   _,_=c.send(ctx,"","Target.closeTarget",map[string]any{"targetId":targetID})
   return
  }
 }
 if s.opts.VirtualPasskey{
  if err:=s.setupVirtualPasskey(ctx,c,sessionID);err!=nil{
   _,_=c.send(ctx,"","Target.closeTarget",map[string]any{"targetId":targetID})
   return
  }
 }
 s.popupMu.Lock()
 s.popupSessions=append(s.popupSessions,popupSession{sessionID:sessionID,targetID:targetID})
 s.popupMu.Unlock()
 _,_=c.send(ctx,sessionID,"Runtime.runIfWaitingForDebugger",nil)
}
func (s *Session) removePopup(sessionID string){
 s.popupMu.Lock()
 var kept []popupSession
 for _,p:=range s.popupSessions{if p.sessionID!=sessionID{kept=append(kept,p)}}
 s.popupSessions=kept
 s.popupMu.Unlock()
 s.mu.Lock()
 if s.pageSess==sessionID{s.pageSess=s.parentSession}
 s.mu.Unlock()
}
// SwitchToApprovedPopup switches the active CDP session to the latest
// allowlisted popup created by the current browser. Its origin must be
// authorized before switching. No raw popup URL is returned.
func (s *Session) SwitchToApprovedPopup(ctx context.Context)(bool,error){
 if len(s.opts.ExternalOrigins)==0{return false,errors.New("popup switching requires external approved browser scope")}
 if err:=s.Start(ctx);err!=nil{return false,err}
 allowed:=map[string]bool{}
 for _,origin:=range s.opts.ExternalOrigins{
  o,err:=canonicalHTTPSOrigin(origin)
  if err!=nil{return false,err}
  allowed[o]=true
 }
 deadline:=time.NewTimer(6*time.Second)
 defer deadline.Stop()
 ticker:=time.NewTicker(100*time.Millisecond)
 defer ticker.Stop()
 for{
  s.popupMu.Lock()
  popups:=append([]popupSession(nil),s.popupSessions...)
  s.popupMu.Unlock()
  if len(popups)>0{
   candidate:=popups[len(popups)-1]
   s.mu.Lock();conn:=s.conn;s.mu.Unlock()
   if conn==nil{return false,errors.New("browser CDP disconnected")}
   probe,err:=conn.send(ctx,candidate.sessionID,"Runtime.evaluate",map[string]any{
    "expression":"location.href","returnByValue":true,
   })
   if err==nil{
    var reply struct{
     Result struct{Value string `json:"value"`} `json:"result"`
    }
    if json.Unmarshal(probe,&reply)==nil&&popupInScope(reply.Result.Value,allowed){
     if strings.HasPrefix(reply.Result.Value,"https://"){
      s.mu.Lock()
      s.pageSess=candidate.sessionID
      s.mu.Unlock()
      return true,nil
     }
    }
   }
  }
  select{
  case <-ctx.Done():return false,ctx.Err()
  case <-deadline.C:return false,nil
  case <-ticker.C:
  }
 }
}
// RestoreMainPage returns the current view to the original application tab.
// It does not change authentication state or bypass any IdP consent.
func (s *Session) RestoreMainPage()error{
 s.mu.Lock();defer s.mu.Unlock()
 if s.parentSession==""||s.conn==nil{return errors.New("original browser tab unavailable")}
 s.pageSess=s.parentSession
 return nil
}

// ParentHasText tests a post-SSO success indicator in the original app tab
// without exposing its text or cookies. If the expected indicator is present,
// it restores the original tab as the active context.
func (s *Session) ParentHasText(ctx context.Context,needle string)(bool,error){
 if len(needle)<4||len(needle)>80{return false,errors.New("invalid parent success indicator")}
 s.mu.Lock()
 conn,main,current:=s.conn,s.parentSession,s.pageSess
 s.mu.Unlock()
 if conn==nil||main==""||main==current{return false,nil}
 encoded,_:=json.Marshal(needle)
 expression:="(document.body && document.body.innerText.includes("+string(encoded)+"))"
 raw,err:=conn.send(ctx,main,"Runtime.evaluate",map[string]any{
  "expression":expression,"returnByValue":true,
 })
 if err!=nil{return false,errors.New("parent page verification unavailable")}
 var result struct{
  Result struct{Value bool `json:"value"`} `json:"result"`
 }
 if json.Unmarshal(raw,&result)!=nil{return false,errors.New("invalid parent page result")}
 if result.Result.Value{
  _=s.RestoreMainPage()
  return true,nil
 }
 return false,nil
}
