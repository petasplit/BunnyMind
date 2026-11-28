package agent

import (
 "strings"
 "testing"
)

func TestProgramPageWithoutTargetExplainsScopeInsteadOfRefusal(t *testing.T) {
 req:=Request{Role:"security",Message:"Bug bounty scope and description - Doctolib bug bounty program and scope:\nhttps://yeswehack.com/programs/doctolib-public-bug-bounty-program.\nSPECIAL NOTES: Test for SQLi, IDOR, SSRF and other critical issues."}
 got:=scopeDocumentationReply(req)
 for _,required:=range []string{"program description","BunnyGuard","Target:","Scope:","No external scan has been started"}{
  if !strings.Contains(got,required){t.Fatalf("missing %q from scope guidance: %s",required,got)}
 }
 if strings.Contains(got,"Sorry, can't assist"){t.Fatal("opaque refusal returned")}
}

func TestProgramPageDoesNotBlockValidStructuredEngagement(t *testing.T) {
 req:=Request{Role:"security",Message:"Read program https://yeswehack.com/programs/doctolib-public-bug-bounty-program\nTarget: https://approved.example\nScope: approved.example"}
 if got:=scopeDocumentationReply(req);got!=""{t.Fatalf("valid target/scope brief blocked: %s",got)}
}
func TestOtherRequestsAreNotHijacked(t *testing.T){
 for _,r:=range []Request{
  {Role:"assistant",Message:"Explain https://yeswehack.com/programs/example"},
  {Role:"security",Message:"Summarize an ordinary local lab fixture"},
  {Role:"security",Depth:1,Message:"https://yeswehack.com/programs/example"},
 }{
  if got:=scopeDocumentationReply(r);got!=""{t.Fatalf("unrelated request intercepted: %+v",r)}
 }
}
