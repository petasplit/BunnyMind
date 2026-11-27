package bunnysarif

import (
 "encoding/json"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/findings"
)
func TestSARIFNoSecretURLsOrRawPOC(t *testing.T){
 data,err:=Build([]findings.Finding{
  {
   ID:"F-001",Title:"Owner access control issue",Severity:findings.High,
   Target:"https://staging.example/invoices/123?token=private-query",
   PoC:"Authorization: Bearer private-token-value",
   Description:"customer PII private-secret",CWE:"CWE-639",
  },
  {
   ID:"F-002",Title:"duplicate",Status:findings.StatusDuplicate,Severity:findings.High,
  },
 })
 if err!=nil{t.Fatal(err)}
 for _,secret:=range []string{"private-query","private-token-value","/invoices/123","customer PII","private-secret"}{
  if strings.Contains(string(data),secret){t.Fatalf("leaked private context: %s",secret)}
 }
 if !strings.Contains(string(data),`"version": "2.1.0"`)||!strings.Contains(string(data),"https://staging.example"){
  t.Fatalf("expected SARIF envelope and safe origin: %s",data)
 }
 var doc Document
 if err:=json.Unmarshal(data,&doc);err!=nil{t.Fatal(err)}
 if len(doc.Runs)!=1||len(doc.Runs[0].Results)!=1{t.Fatal("duplicate finding included")}
}
func TestSARIFNoFalseVerificationAssertion(t *testing.T){
 data,err:=Build([]findings.Finding{{ID:"F-001",Title:"candidate",Status:findings.StatusConfirmed,Severity:findings.Critical}})
 if err!=nil{t.Fatal(err)}
 if !strings.Contains(string(data),"unattested; requires independent verification"){t.Fatal("model confirmation became verified verdict")}
}
