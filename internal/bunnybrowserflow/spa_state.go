package bunnybrowserflow

import (
 "context"
 "errors"
 "net/url"
 "strings"
 "time"
)

type MagicLinkProvider interface {
 WaitLink(context.Context,string,map[string]bool,[]string)(string,error)
}
func approvedOriginOf(raw string,approved map[string]bool)(string,error){
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||u.Scheme!="https"||
 u.Hostname()==""||(u.Port()!=""&&u.Port()!="443"){
  return "",errors.New("browser navigation outside approved HTTPS origins")
 }
 origin:="https://"+strings.ToLower(u.Hostname())
 if !approved[origin]{return "",errors.New("browser left approved authentication scope")}
 return origin,nil
}
// Bounded DOM-state polling accommodates client-side hydration, delayed
// redirects, and async OTP steps without repeatedly submitting a form.
// The result is observed UI progress, never a claim of security impact.
func awaitAuthProgress(ctx context.Context,b Browser,discover DiscoveryBrowser,
 prevSignature,oldURL,successText string,allowed map[string]bool,idps []string)(bool,error){
 deadline:=time.NewTimer(4*time.Second)
 defer deadline.Stop()
 tick:=time.NewTicker(200*time.Millisecond)
 defer tick.Stop()
 for {
  urlNow,err:=b.CurrentURL(ctx)
  if err!=nil{return false,errors.New("browser navigation unavailable")}
  if _,err:=approvedOriginOf(urlNow,allowed);err!=nil{return false,err}
  if signed,e:=b.Contains(ctx,successText);e==nil&&signed{return true,nil}
  var state AuthPageState
  if scoped,ok:=discover.(ScopedDiscoveryBrowser);ok{
   state,err=scoped.DiscoverAuthScoped(ctx,idps)
  }else{state,err=discover.DiscoverAuth(ctx)}
  if err==nil&&validateDiscovery(state)==nil{
   // Ignore a transient empty root while a SPA hydrates.
   if len(state.Fields)>0||state.SubmitSelector!=""||state.ProviderSelector!=""{
    if uniqueState(state)!=prevSignature{return false,nil}
   }
  }
  if urlNow!=oldURL&&err==nil&&state.Kind!="unknown"{return false,nil}
  select{
  case <-ctx.Done():return false,ctx.Err()
  case <-deadline.C:return false,nil
  case <-tick.C:
  }
 }
}
