package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "strings"

 "github.com/enowdev/antares/internal/browser"
)

// ChromiumFactory creates a fresh, private Chromium profile for each actor.
// This factory is intentionally limited to numeric-loopback fixtures.
type ChromiumFactory struct{
 Executable string
}
type chromeDriver struct{ session *browser.Session }
func (f ChromiumFactory) New(ctx context.Context,actor,origin string)(Browser,error){
 if _,err:=Origin(origin);err!=nil{return nil,err}
 s:=browser.New(browser.Options{
  Executable:f.Executable,Headless:true,Width:1050,Height:720,
  LoopbackOrigin:origin,
 })
 if err:=s.Start(ctx);err!=nil{s.Stop();return nil,err}
 return &chromeDriver{session:s},nil
}
func (d *chromeDriver) Close(){d.session.Stop()}
func (d *chromeDriver) Navigate(ctx context.Context,raw string)error{
 return d.session.Navigate(ctx,raw)
}
func jsQuoted(s string)string{
 b,_:=json.Marshal(s)
 return string(b)
}
func (d *chromeDriver) Fill(ctx context.Context,selector,value string)error{
 if !(validSelector.MatchString(selector)||safeDiscoverySelector.MatchString(selector))||len(value)==0||len(value)>256{return errors.New("invalid trusted field input")}
 // Keep credential bytes out of injected JavaScript source: only the
 // operator-locked selector goes into JS, followed by a CDP text event.
 script:=fmt.Sprintf(`(() => {
  const el=document.querySelector(%s);
  if(!el || el.disabled || (el.tagName!=='INPUT'&&el.tagName!=='TEXTAREA')) return 'missing';
  el.focus();
  const proto=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
  const setter=Object.getOwnPropertyDescriptor(proto,'value').set;
  setter.call(el,'');
  el.dispatchEvent(new Event('input',{bubbles:true}));
  return 'ok';
 })()`,jsQuoted(selector))
 out,err:=d.session.EvalString(ctx,script)
 if err!=nil||out!="ok"{return errors.New("trusted field not found")}
 if err:=d.session.InsertText(ctx,value);err!=nil{return errors.New("trusted field entry failed")}
 return nil
}
func (d *chromeDriver) Click(ctx context.Context,selector string)error{
 if !(validSelector.MatchString(selector)||safeDiscoverySelector.MatchString(selector)){return errors.New("invalid trusted selector")}
 script:=fmt.Sprintf(`(() => {
  const el=document.querySelector(%s);
  if(!el || el.disabled) return 'missing';
  el.click();
  return 'ok';
 })()`,jsQuoted(selector))
 out,err:=d.session.EvalString(ctx,script)
 if err!=nil||out!="ok"{return errors.New("trusted control not found")}
 _=d.session.WaitReady(ctx,4_000_000_000)
 return nil
}
func (d *chromeDriver) Contains(ctx context.Context,needle string)(bool,error){
 if needle==""||len(needle)>80||strings.ContainsAny(needle,"\r\n"){return false,errors.New("invalid assertion")}
 script:=fmt.Sprintf(`(document.body && document.body.innerText.includes(%s)) ? 'yes' : 'no'`,jsQuoted(needle))
 out,err:=d.session.EvalString(ctx,script)
 if err!=nil{return false,errors.New("local assertion not available")}
 return out=="yes",nil
}
func (d *chromeDriver) CurrentURL(ctx context.Context)(string,error){
 return d.session.URL(ctx)
}
