package tools

import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)

const receiptPublicKeyFileEnv = "BUNNYMIND_RECEIPT_PUBLIC_KEY_FILE"

// verifyLabReceiptsTool accepts only a public verification key.
// Signing requires a separate lab recorder; no signing secret belongs here.
type verifyLabReceiptsTool struct{}
func (verifyLabReceiptsTool) Name()string{return "verify_lab_receipts"}
func (verifyLabReceiptsTool) Description()string{
 return "Verify Ed25519 signatures on synthetic or isolated-lab observation receipts, "+
 "then assess repeated positive and negative-control assertions. "+
 "Requires a pinned public key and engagement manifest. "+
 "A signature authenticates the recorder's key, NOT a vulnerability or exploit; no HTTP requests are made."
}
func (verifyLabReceiptsTool) RequiresApproval()bool{return false}
func (verifyLabReceiptsTool) Schema()map[string]any{
 return schema(map[string]any{
  "bundle":map[string]any{
   "type":"object",
   "description":"Bundle of 1..64 signed observations from a separately operated trusted recorder.",
   "properties":map[string]any{
    "engagement_id":prop("string","Authorized engagement ID."),
    "run_id":prop("string","Trusted test run identifier."),
    "case_id":prop("string","Local fixture or evaluation case ID."),
    "receipts":map[string]any{"type":"array","items":map[string]any{"type":"object"}},
   },
   "required":[]string{"engagement_id","run_id","case_id","receipts"},
  },
 },"bundle")
}
func (verifyLabReceiptsTool) Execute(_ context.Context,in Input)Result{
 var args struct{Bundle bunnyreceipt.Bundle `json:"bundle"`}
 if err:=in.Bind(&args);err!=nil{return Errorf("invalid bundle input: %v",err)}
 policyPath:=strings.TrimSpace(os.Getenv(bunnyguard.EnvPolicy))
 if policyPath==""{return Errorf("lab receipt verification requires an explicit BunnyGuard engagement")}
 guard,err:=bunnyguard.New(policyPath)
 if err!=nil{return Errorf("invalid engagement policy: %v",err)}
 if guard.Manifest().EngagementID!=args.Bundle.EngagementID{
  return Errorf("receipt bundle is not bound to this engagement")
 }
 publicPath:=strings.TrimSpace(os.Getenv(receiptPublicKeyFileEnv))
 if publicPath==""||!filepath.IsAbs(publicPath){return Errorf("pinned public key file path is required")}
 blob,err:=os.ReadFile(publicPath)
 if err!=nil{return Errorf("cannot load pinned public key: %v",err)}
 raw,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(blob)))
 if err!=nil||len(raw)!=ed25519.PublicKeySize{return Errorf("pinned public key is invalid")}
 result,err:=bunnyreceipt.Verify(ed25519.PublicKey(raw),args.Bundle)
 if err!=nil{return Errorf("receipt signature verification failed: %v",err)}
 b,err:=json.MarshalIndent(result,"","  ")
 if err!=nil{return Errorf("receipt summary serialization failed: %v",err)}
 return Text(string(b))
}
