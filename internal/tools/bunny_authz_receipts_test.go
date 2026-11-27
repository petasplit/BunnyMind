package tools

import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/bunnyauthz"
 "github.com/enowdev/antares/internal/bunnyguard"
 "github.com/enowdev/antares/internal/bunnyreceipt"
)
const testOwnerKey="SYNTHETIC_OWNER_KEY_FOR_LAB_0123"
const testForeignKey="SYNTHETIC_FOREIGN_KEY_FOR_LAB_4567"
func authzToolFixture(t *testing.T)(Input,bunnyauthz.Plan,bunnyauthz.Capture,ed25519.PublicKey) {
 t.Helper()
 marker:="SYNTHETIC_OWNER_LAB_MARKER"
 srv:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  if r.URL.Path!="/owned" {w.WriteHeader(404);return}
  switch r.Header.Get("Authorization"){
  case "Bearer "+testOwnerKey,"Bearer "+testForeignKey:
   _,_=w.Write([]byte(marker))
  case "":
   w.WriteHeader(401)
  default:
   w.WriteHeader(403)
  }
 }))
 t.Cleanup(srv.Close)
 pub,priv,err:=bunnyreceipt.Keypair();if err!=nil{t.Fatal(err)}
 plan:=bunnyauthz.Plan{
  EngagementID:"synthetic_auth_tool",RunID:"run_1",CaseID:"case_1",
  Origin:srv.URL,ResourcePath:"/owned",Marker:marker,
 }
 cap,err:=bunnyauthz.Record(context.Background(),plan,priv,bunnyauthz.Tokens{
  Owner:testOwnerKey,Foreign:testForeignKey,
 })
 if err!=nil{t.Fatal(err)}
 policy:=bunnyguard.Policy{
  EngagementID:plan.EngagementID,
  AllowedOrigins:[]string{srv.URL},AllowedMethods:[]string{"GET"},
  MaxNetworkCalls:8,
 }
 raw,err:=json.Marshal(policy);if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 manifest:=filepath.Join(dir,"policy.json")
 if err:=os.WriteFile(manifest,raw,0600);err!=nil{t.Fatal(err)}
 t.Setenv(bunnyguard.EnvPolicy,manifest)
 publicPath:=filepath.Join(dir,"recorder-pub.key")
 if err:=os.WriteFile(publicPath,[]byte(base64.StdEncoding.EncodeToString(pub)),0600);err!=nil{t.Fatal(err)}
 t.Setenv(receiptPublicKeyFileEnv,publicPath)
 body,err:=json.Marshal(map[string]any{
  "plan":plan,"owner_bundle":cap.OwnerBundle,"cross_user_bundle":cap.CrossUserBundle,
 })
 if err!=nil{t.Fatal(err)}
 return Input{SessionID:"authorized_test_session",Args:body},plan,cap,pub
}
func TestAssessAuthzReceiptsToolLocal(t *testing.T) {
 in,_,_,_:=authzToolFixture(t)
 result:=(assessAuthzReceiptsTool{}).Execute(context.Background(),in)
 if result.IsError||!strings.Contains(result.Content,"cross_persona_marker_observed_in_lab") {
  t.Fatalf("unexpected signed lab decision: %+v",result)
 }
 for _,secret:=range []string{testOwnerKey,testForeignKey} {
  if strings.Contains(result.Content,secret) { t.Fatal("test bearer token leaked into tool result") }
 }
}
func TestAssessAuthzReceiptsToolRejectsUnknownFields(t *testing.T) {
 in,p,c,_:=authzToolFixture(t)
 body,err:=json.Marshal(map[string]any{
  "plan":p,"owner_bundle":c.OwnerBundle,
  "cross_user_bundle":c.CrossUserBundle,"credentials":"never-accept-secrets",
 })
 if err!=nil{t.Fatal(err)}
 in.Args=body
 result:=(assessAuthzReceiptsTool{}).Execute(context.Background(),in)
 if !result.IsError {t.Fatal("extra credential field was silently accepted")}
}
func TestAssessAuthzReceiptsToolRejectsCrossEngagement(t *testing.T) {
 in,p,c,_:=authzToolFixture(t)
 p.EngagementID="other_engagement"
 body,err:=json.Marshal(map[string]any{
  "plan":p,"owner_bundle":c.OwnerBundle,"cross_user_bundle":c.CrossUserBundle,
 })
 if err!=nil{t.Fatal(err)}
 in.Args=body
 result:=(assessAuthzReceiptsTool{}).Execute(context.Background(),in)
 if !result.IsError {t.Fatal("cross-engagement result incorrectly accepted")}
}
