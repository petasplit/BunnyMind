// BunnyMind synthetic authz demo: a disposable localhost-only web service.
// It never probes third-party hosts and does not accept real credentials.
package main

import (
 "context"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "flag"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"

 "github.com/enowdev/antares/internal/bunnyauthz"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)

// testPersonaToken creates an ephemeral random synthetic bearer token.
// It is never logged, serialized, or passed to an agent tool.
func testPersonaToken()(string,error){
 b:=make([]byte,32)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(b),nil
}
func main(){
 vulnerable:=flag.Bool("vulnerable",false,"simulate an intentionally vulnerable local cross-user access rule")
 jsonOnly:=flag.Bool("json",false,"emit JSON-only result for native CI")
 flag.Parse()
 owner,err:=testPersonaToken()
 if err!=nil{fmt.Fprintln(os.Stderr,"cannot create owner test persona:",err);os.Exit(1)}
 foreign,err:=testPersonaToken()
 if err!=nil{fmt.Fprintln(os.Stderr,"cannot create foreign test persona:",err);os.Exit(1)}
 const marker="SYNTHETIC_OWNER_RESOURCE_PROOF_123"
 fixture:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.Method!="GET"||r.URL.Path!="/accounts/owner"{
   w.WriteHeader(http.StatusNotFound)
   return
  }
  switch r.Header.Get("Authorization"){
  case "Bearer "+owner:
   w.WriteHeader(http.StatusOK)
   _,_=w.Write([]byte(marker))
  case "Bearer "+foreign:
   if *vulnerable{
    w.WriteHeader(http.StatusOK)
    _,_=w.Write([]byte(marker))
   }else{
    w.WriteHeader(http.StatusForbidden)
   }
  case "":
   w.WriteHeader(http.StatusUnauthorized)
  default:
   w.WriteHeader(http.StatusForbidden)
  }
 }))
 defer fixture.Close()
 pub,priv,err:=bunnyreceipt.Keypair()
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 p:=bunnyauthz.Plan{EngagementID:"demo_local_lab",RunID:"demo_run",
  CaseID:"synthetic_owner_access",Origin:fixture.URL,
  ResourcePath:"/accounts/owner",Marker:marker}
 captured,err:=bunnyauthz.Record(context.Background(),p,priv,bunnyauthz.Tokens{
  Owner:owner,Foreign:foreign,
 })
 if err!=nil{fmt.Fprintln(os.Stderr,"lab capture:",err);os.Exit(1)}
 assessment,err:=bunnyauthz.Assess(pub,p,captured)
 if err!=nil{fmt.Fprintln(os.Stderr,"lab assessment:",err);os.Exit(1)}
 // No signing key, session token, response body or marker is emitted.
 output,err:=json.MarshalIndent(assessment,"","  ")
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 if !*jsonOnly{
  fmt.Println("BunnyMind v0.13 synthetic authorization lab")
  fmt.Println("Warning: signer and fixture share a process; results demonstrate local-only test behavior.")
 }
 fmt.Println(string(output))
 if (!*vulnerable && assessment.Outcome!="cross_persona_denied_in_lab") ||
  (*vulnerable && assessment.Outcome!="cross_persona_marker_observed_in_lab"){
  fmt.Fprintln(os.Stderr,"synthetic scenario did not produce the expected comparison")
  os.Exit(1)
 }
}
