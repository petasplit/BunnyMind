package tools

import (
 "context"
 "encoding/base64"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)
func signedToolInput(t *testing.T)(Input,func()string){
 t.Helper()
 dir:=t.TempDir()
 policy:=bunnyguard.Policy{
  EngagementID:"local_lab",AllowedOrigins:[]string{"http://127.0.0.1:8765"},
  MaxNetworkCalls:8,AllowedMethods:[]string{"GET"},
 }
 body,err:=json.Marshal(policy);if err!=nil{t.Fatal(err)}
 p:=filepath.Join(dir,"policy.json")
 if err:=os.WriteFile(p,body,0600);err!=nil{t.Fatal(err)}
 t.Setenv(bunnyguard.EnvPolicy,p)
 pub,priv,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)}
 keyfile:=filepath.Join(dir,"recorder-public.key")
 if err:=os.WriteFile(keyfile,[]byte(base64.StdEncoding.EncodeToString(pub)),0600);err!=nil{t.Fatal(err)}
 t.Setenv(receiptPublicKeyFileEnv,keyfile)
 bundle:=bunnyreceipt.Bundle{EngagementID:"local_lab",RunID:"run_1",CaseID:"case_1"}
 for _,id:=range []string{"p1","p2","c1","c2"}{
  kind:="positive";present:=true
  if id[0]=='c'{kind="control";present=false}
  observation:=bunnyreceipt.Observation{Version:1,EngagementID:"local_lab",RunID:"run_1",CaseID:"case_1",
   SampleID:id,Kind:kind,Method:"GET",Origin:"http://127.0.0.1:8765",
   RequestSHA256:bunnyreceipt.Dig("request:"+id),ResponseSHA256:bunnyreceipt.Dig("response:"+id),
   MarkerSHA256:bunnyreceipt.Dig("marker"),ResponseStatus:200,MarkerPresent:present,
   RecordedAt:"2026-11-27T09:00:00Z"}
  signed,err:=bunnyreceipt.Sign(priv,observation);if err!=nil{t.Fatal(err)}
  bundle.Receipts=append(bundle.Receipts,signed)
 }
 makeInput:=func()string{
  payload,err:=json.Marshal(map[string]any{"bundle":bundle})
  if err!=nil{t.Fatal(err)}
  return string(payload)
 }
 return Input{SessionID:"session-test",Args:json.RawMessage(makeInput())},makeInput
}
func TestVerifyLabReceiptsToolConsistent(t *testing.T){
 in,_:=signedToolInput(t)
 res:=(verifyLabReceiptsTool{}).Execute(context.Background(),in)
 if res.IsError||!strings.Contains(res.Content,"consistent-signed-observations"){t.Fatalf("%+v",res)}
}
func TestVerifyLabReceiptsToolNoManifest(t *testing.T){
 in,_:=signedToolInput(t)
 t.Setenv(bunnyguard.EnvPolicy,"")
 res:=(verifyLabReceiptsTool{}).Execute(context.Background(),in)
 if !res.IsError{t.Fatal("missing engagement manifest accepted")}
}
func TestVerifyLabReceiptsToolWrongEngagement(t *testing.T){
 in,_:=signedToolInput(t)
 t.Setenv(bunnyguard.EnvPolicy,filepath.Join(t.TempDir(),"absent.json"))
 res:=(verifyLabReceiptsTool{}).Execute(context.Background(),in)
 if !res.IsError{t.Fatal("invalid policy accepted")}
}
func TestVerifyLabReceiptsToolWrongKey(t *testing.T){
 in,_:=signedToolInput(t)
 pub,_,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)}
 wrong:=filepath.Join(t.TempDir(),"wrong.key")
 if err:=os.WriteFile(wrong,[]byte(base64.StdEncoding.EncodeToString(pub)),0600);err!=nil{t.Fatal(err)}
 t.Setenv(receiptPublicKeyFileEnv,wrong)
 res:=(verifyLabReceiptsTool{}).Execute(context.Background(),in)
 if !res.IsError||!strings.Contains(res.Content,"signature"){t.Fatalf("wrong key not detected %+v",res)}
}
