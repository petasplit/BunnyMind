package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "crypto/rand"
 "os"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"

 "github.com/enowdev/antares/internal/browser"
 "github.com/enowdev/antares/internal/bunnyartifact"
)
func TestChromeEncryptedOTPScreenshotAndOfficialTestWidgetClick(t *testing.T){
 chrome:=os.Getenv("BUNNY_CHROME")
 if _,err:=browser.FindExecutable(chrome);err!=nil{
  if chrome!=""{t.Fatal(err)}
  t.Skip("Chromium unavailable")
 }
 site:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/html")
  _,_=w.Write([]byte(`<!doctype html><html><body>
   <h1>Test account verification</h1>
   <input autocomplete="one-time-code" name="otp" placeholder="Verification code">
   <div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"
      onclick="document.querySelector('#status').textContent='provider fixture clicked'"
      style="width:150px;height:80px;border:1px solid">Test widget</div>
   <div id="status"></div>
   <div id="production" data-sitekey="not-a-test-key"
      onclick="document.querySelector('#status').textContent='production clicked'"
      style="width:150px;height:80px"></div>
  </body></html>`))
 }))
 defer site.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),80*time.Second)
 defer cancel()
 s:=browser.New(browser.Options{Executable:chrome,Headless:true,LoopbackOrigin:site.URL})
 defer s.Stop()
 if err:=s.Navigate(ctx,site.URL);err!=nil{t.Fatal(err)}
 key:=make([]byte,32);_,_=rand.Read(key)
 vault:=&screenshotVault{root:t.TempDir(),key:key}
 driver:=&chromeDriver{session:s,vault:vault}
 record,err:=driver.RecordScreenshot(ctx,"owner","otp")
 if err!=nil||record.File==""||record.SHA256==""{t.Fatalf("screenshot not saved: %v %+v",err,record)}
 png,err:=bunnyartifact.Open(vault.root,"owner-otp-1","screenshot",key)
 if err!=nil||len(png)<10||png[0]!=137{t.Fatal("encrypted PNG not recoverable")}
 clicked,err:=driver.ClickOfficialTestChallenge(ctx)
 if err!=nil||!clicked{t.Fatalf("approved test widget was not clicked: %v %v",clicked,err)}
 yes,err:=driver.Contains(ctx,"provider fixture clicked")
 if err!=nil||!yes{t.Fatalf("genuine widget click not reflected in DOM: %v",err)}
 receipts,err:=driver.CaptureTraffic(ctx,"owner",1,map[string]bool{site.URL:true})
 if err!=nil||len(receipts)==0{t.Fatalf("Chrome HTTP evidence capture unavailable: %v, len=%d",err,len(receipts))}
 if receipts[0].EncryptedCapture==""||receipts[0].CaptureSHA256==""{
  t.Fatalf("browser evidence was not encrypted: %+v",receipts[0])
 }
 raw,err:=bunnyartifact.Open(vault.root,"owner-browser-http-1","browser_http",key)
 if err!=nil{t.Fatal(err)}
 var private BrowserProofBatch
 if err:=json.Unmarshal(raw,&private);err!=nil{t.Fatal(err)}
 if len(private.Exchanges)==0||private.Exchanges[0].Method!="GET"{
  t.Fatalf("HTTP request not preserved: %+v",private)
 }
 for _,item:=range receipts{
  if strings.Contains(item.Origin,"data-sitekey")||strings.Contains(item.PathSHA256,"private"){
   t.Fatal("raw browser page data in metadata")
  }
 }
 if strings.Contains(record.File,"private"){t.Fatal("file metadata contains page data")}
}
