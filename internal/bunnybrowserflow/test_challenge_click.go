package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
)

// OfficialTestChallengeInteraction emulates an ordinary user click only on a
// visible provider widget with a documented public test sitekey. It never
// fabricates tokens or clicks arbitrary production CAPTCHA controls.
type OfficialTestChallengeInteraction interface{
 ClickOfficialTestChallenge(context.Context)(bool,error)
}
const testWidgetCenterJS = `(() => {
 const testKeys=new Set([
  '1x00000000000000000000AA','1x00000000000000000000BB',
  '2x00000000000000000000AB','2x00000000000000000000BB',
  '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'
 ]);
 const widget=Array.from(document.querySelectorAll('.cf-turnstile[data-sitekey],.g-recaptcha[data-sitekey], [data-sitekey]'))
  .find(el=>testKeys.has(el.getAttribute('data-sitekey')||'') && el.getClientRects().length>0);
 if(!widget)return {eligible:false};
 const frame=Array.from(document.querySelectorAll('iframe')).find(el=>{
  const src=(el.getAttribute('src')||'').toLowerCase();
  return (/challenges.cloudflare.com|google.com\/recaptcha|recaptcha.net/.test(src)) &&
    el.getClientRects().length>0;
 });
 const target=frame||widget;
 const rect=target.getBoundingClientRect();
 if(rect.width<14||rect.height<14)return {eligible:false};
 const x=Math.round(rect.left+Math.min(rect.width/2,35));
 const y=Math.round(rect.top+Math.min(rect.height/2,35));
 if(x<0||y<0||x>innerWidth||y>innerHeight)return {eligible:false};
 return {eligible:true,x,y};
})()`
func (d *chromeDriver) ClickOfficialTestChallenge(ctx context.Context)(bool,error){
 if d.session==nil{return false,errors.New("browser session missing")}
 raw,err:=d.session.Eval(ctx,testWidgetCenterJS)
 if err!=nil{return false,errors.New("provider widget not inspectable")}
 var result struct{
  Eligible bool `json:"eligible"`
  X float64 `json:"x"`
  Y float64 `json:"y"`
 }
 if err:=json.Unmarshal(raw,&result);err!=nil{return false,errors.New("invalid provider widget geometry")}
 if !result.Eligible{return false,nil}
 if err:=d.session.ClickXY(ctx,result.X,result.Y);err!=nil{
  return false,errors.New("test widget click was not accepted by browser")
 }
 return true,nil
}
var _ OfficialTestChallengeInteraction=(*chromeDriver)(nil)
