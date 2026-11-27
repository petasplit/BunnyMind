package bunnyfindingchat

import (
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/findings"
)
func sample() findings.Finding{
 return findings.Finding{
  ID:"F-001",Title:"Test issue",Severity:findings.High,Status:findings.StatusNew,
  PoC:"Authorization: Bearer highly-sensitive-token",
  Reproduce:"GET /private?token=secret-check",
  Impact:"Access to test resource only",Remediation:"Check ownership",
 }
}
func TestFindingChatPersistsButNeverEchosRawProof(t *testing.T){
 store:=New(t.TempDir())
 for _,q:=range []string{"What proof is recorded?","How should we fix this?"}{
  turns,err:=store.Append("session-a","F-001",q,sample())
  if err!=nil{t.Fatal(err)}
  if len(turns)%2!=0{t.Fatal("incomplete exchange")}
 }
 reopened:=New(store.root)
 turns,err:=reopened.Load("session-a","F-001")
 if err!=nil||len(turns)!=4{t.Fatalf("conversation did not persist %v %+v",err,turns)}
 for _,turn:=range turns{
  for _,secret:=range []string{"highly-sensitive-token","secret-check","GET /private"}{
   if strings.Contains(turn.Text,secret){t.Fatalf("leaked raw proof: %s",secret)}
  }
 }
 if len(turns[1].EvidenceSHA256)!=64{t.Fatal("missing evidence provenance digest")}
 other,err:=store.Load("session-b","F-001")
 if err!=nil||len(other)!=0{t.Fatal("cross-session chat history exposed")}
}
func TestRejectSecretsAndInvalidConversationKeys(t *testing.T){
 store:=New(t.TempDir())
 for _,question:=range []string{"Bearer token-is-private","password=123456789","token=private","a","a\nsecret"}{
  if _,err:=store.Append("session-a","F-001",question,sample());err==nil{
   t.Fatalf("accepted dangerous question: %q",question)
  }
 }
 if _,err:=store.Append("../escape","F-1","hello",sample());err==nil{
  t.Fatal("accepted malformed finding ID")
 }
}
func TestConversationHistoryBounded(t *testing.T){
 store:=New(t.TempDir())
 for i:=0;i<30;i++{
  if _,err:=store.Append("session-a","F-001","Please review evidence again",sample());err!=nil{t.Fatal(err)}
 }
 turns,_:=store.Load("session-a","F-001")
 if len(turns)!=40{t.Fatalf("history exceeded limit: %d",len(turns))}
}
