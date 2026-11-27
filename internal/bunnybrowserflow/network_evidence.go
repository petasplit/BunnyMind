package bunnybrowserflow

import (
 "context"
 "encoding/base64"
 "encoding/json"
 "errors"
 "net/url"
 "strconv"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/browser"
)

const maxBrowserHTTPExchanges=32
const maxBrowserResponseBytes=65536
// BrowserHTTPExchange is PRIVATE raw evidence, never a model-facing schema.
// Sensitive URLs, request headers, cookies, submitted values and response
// bodies are stored only inside the encrypted vault.
type BrowserHTTPExchange struct{
 Method string `json:"method"`
 URL string `json:"url"`
 RequestHeaders map[string]string `json:"request_headers"`
 RequestBody string `json:"request_body,omitempty"`
 ResponseStatus int `json:"response_status,omitempty"`
 ResponseHeaders map[string]string `json:"response_headers,omitempty"`
 ResponseBodyB64 string `json:"response_body_b64,omitempty"`
 ResponseBodyPresent bool `json:"response_body_present"`
 ResponseBodyTruncated bool `json:"response_body_truncated,omitempty"`
 ErrorObserved bool `json:"error_observed,omitempty"`
}
type BrowserProofBatch struct{
 Actor string `json:"actor"`
 Step int `json:"step"`
 CapturedAt string `json:"captured_at"`
 Source string `json:"source"`
 Exchanges []BrowserHTTPExchange `json:"exchanges"`
 Limitations string `json:"limitations"`
}
func (d *chromeDriver) captureBrowserRaw(ctx context.Context,actor string,step int,
 requests []browser.NetworkRequest,allowed map[string]bool)(bunnyartifact.Receipt,error){
 if d.vault==nil{return bunnyartifact.Receipt{},nil}
 if !validActor.MatchString(actor)||step<1||step>10000{return bunnyartifact.Receipt{},errors.New("invalid browser evidence actor/step")}
 batch:=BrowserProofBatch{Actor:actor,Step:step,CapturedAt:time.Now().UTC().Format(time.RFC3339Nano),
  Source:"Chromium Network.* CDP events",
  Exchanges:[]BrowserHTTPExchange{},
  Limitations:"Reconstructed HTTP request/response fields observed by Chrome, not decrypted wire-byte capture. Response bodies are capped at 64 KiB and may be missing or evicted; note the explicit flags.",
 }
 for _,r:=range requests{
  if len(batch.Exchanges)>=maxBrowserHTTPExchanges{break}
  u,err:=url.Parse(r.URL)
  if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||u.Hostname()==""{continue}
  origin:=strings.ToLower(u.Scheme+"://"+u.Host)
  if !allowed[origin]{
   if u.Scheme=="https"&&u.Port()=="443"{
    origin="https://"+strings.ToLower(u.Hostname())
   }
  }
  if !allowed[origin]{continue}
  switch r.Method{case "GET","HEAD","OPTIONS","POST":default:continue}
  item:=BrowserHTTPExchange{Method:r.Method,URL:r.URL,
   RequestHeaders:r.Headers,RequestBody:r.PostData,ErrorObserved:r.Failed!=""}
  if len(item.RequestBody)>maxBrowserResponseBytes{
   item.RequestBody=item.RequestBody[:maxBrowserResponseBytes]
  }
  if r.Response!=nil{
   item.ResponseStatus=r.Response.Status
   item.ResponseHeaders=r.Response.Headers
   if r.RequestID!=""{
    text,typ,e:=d.session.ResponseBody(ctx,r.RequestID)
    if e==nil{
     var body []byte
     if strings.HasPrefix(typ,"application/base64;"){
      body,e=base64.StdEncoding.DecodeString(text)
     }else{body=[]byte(text)}
     if e==nil{
      if len(body)>maxBrowserResponseBytes{
       body=body[:maxBrowserResponseBytes]
       item.ResponseBodyTruncated=true
      }
      item.ResponseBodyB64=base64.StdEncoding.EncodeToString(body)
      item.ResponseBodyPresent=true
     }
    }
   }
  }
  batch.Exchanges=append(batch.Exchanges,item)
 }
 if len(batch.Exchanges)==0{return bunnyartifact.Receipt{},nil}
 serialized,err:=json.Marshal(batch)
 if err!=nil{return bunnyartifact.Receipt{},err}
 name:=actor+"-browser-http-"+strconv.Itoa(step)
 d.vault.mu.Lock()
 defer d.vault.mu.Unlock()
 return bunnyartifact.Store(d.vault.root,name,"browser_http",serialized,d.vault.key)
}
