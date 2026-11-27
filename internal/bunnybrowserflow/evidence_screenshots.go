package bunnybrowserflow

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "os"
 "path/filepath"
 "strconv"
 "sync"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/browser"
)

type EvidenceScreenshotter interface{
 RecordScreenshot(context.Context,string,string)(bunnyartifact.Receipt,error)
}
type screenshotVault struct{
 root string
 key []byte
 mu sync.Mutex
 shots int
}
// captureRoot is an explicit private output path. Hashing the engagement ID
// prevents slash or traversal characters in configuration from forming paths.
func captureRoot(root,engagement string)string{
 digest:=sha256.Sum256([]byte(engagement))
 return filepath.Join(root,hex.EncodeToString(digest[:8]))
}
func newCaptureVault(root,engagement string)(*screenshotVault,error){
 if root==""{return nil,nil}
 if len(root)>2048{return nil,errors.New("screenshot output path too long")}
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return nil,err}
 dest:=captureRoot(root,engagement)
 if err:=os.MkdirAll(dest,0700);err!=nil{return nil,err}
 return &screenshotVault{root:dest,key:key},nil
}
func (d *chromeDriver) RecordScreenshot(ctx context.Context,actor,stage string)(bunnyartifact.Receipt,error){
 if d.vault==nil{return bunnyartifact.Receipt{},nil}
 if !validActor.MatchString(actor)||len(stage)==0||len(stage)>32{
  return bunnyartifact.Receipt{},errors.New("invalid screenshot actor or state")
 }
 for _,c:=range stage{
  if (c<'a'||c>'z')&&c!='_'{
   return bunnyartifact.Receipt{},errors.New("unsupported screenshot stage")
  }
 }
 d.vault.mu.Lock()
 defer d.vault.mu.Unlock()
 if d.vault.shots>=64{return bunnyartifact.Receipt{},errors.New("evidence screenshot limit reached")}
 raw,err:=d.session.Screenshot(ctx,false)
 if err!=nil{return bunnyartifact.Receipt{},errors.New("Chromium screenshot unavailable")}
 if len(raw)<8||raw[0]!=137||raw[1]!='P'||raw[2]!='N'||raw[3]!='G'{
  return bunnyartifact.Receipt{},errors.New("browser did not return a PNG capture")
 }
 name:=actor+"-"+stage+"-"+strconv.Itoa(d.vault.shots+1)
 receipt,err:=bunnyartifact.Store(d.vault.root,name,"screenshot",raw,d.vault.key)
 if err!=nil{return bunnyartifact.Receipt{},err}
 d.vault.shots++
 return receipt,nil
}
// RecordStateScreenshot stores screenshots before OTP and CAPTCHA interactions,
// plus after form submission. No raw image bytes enter a tool response.
func stateScreenshotStage(state AuthPageState)string{
 if state.Challenge=="anti_bot"{return "captcha"}
 for _,field:=range state.Fields{
  if field.Role=="otp"{return "otp"}
 }
 switch state.Kind{
 case "login":return "login"
 case "signup":return "signup"
 case "verification":return "verification"
 default:return "page"
 }
}
var _ EvidenceScreenshotter=(*chromeDriver)(nil)
var _ = browser.New
