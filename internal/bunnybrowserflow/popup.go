package bunnybrowserflow

import (
 "context"
 "errors"
)

// PopupBrowser is optional and only implemented by a Chromium session whose
// networking has been constrained by the operator-approved origin proxy.
type PopupBrowser interface{
 SwitchToApprovedPopup(context.Context)(bool,error)
 RestoreMainPage()error
 ParentHasText(context.Context,string)(bool,error)
}
func (d *chromeDriver) SwitchToApprovedPopup(ctx context.Context)(bool,error){
 if d.session==nil{return false,errors.New("browser not initialized")}
 return d.session.SwitchToApprovedPopup(ctx)
}
func (d *chromeDriver) RestoreMainPage()error{
 if d.session==nil{return errors.New("browser not initialized")}
 return d.session.RestoreMainPage()
}
func (d *chromeDriver) ParentHasText(ctx context.Context,text string)(bool,error){
 if d.session==nil{return false,errors.New("browser not initialized")}
 return d.session.ParentHasText(ctx,text)
}
