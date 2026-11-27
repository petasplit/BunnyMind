package bunnyhar

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestScopeAuthAndSecretRedaction(t *testing.T){
	raw:=StringFixture()
	report,err:=Analyze(strings.NewReader(raw),[]string{"https://example.test/"})
	if err!=nil{t.Fatal(err)}
	if report.TotalEntries!=4||report.InScope!=2||report.OutOfScope!=1||report.Invalid!=1{
		t.Fatalf("bad scope counts: %+v",report)
	}
	if report.UniqueEndpoints!=1||report.AuthenticatedRequests!=2||
		report.StatusClasses["2xx"]!=1||report.StatusClasses["4xx"]!=1{
		t.Fatalf("bad inventory counts: %+v",report)
	}
	encoded,err:=json.Marshal(report);if err!=nil{t.Fatal(err)}
	for _,secret:=range []string{"secret-session-token","cookie-secret","my-private-query","/invoices/123"}{
		if strings.Contains(string(encoded),secret){t.Fatalf("HAR secret or path leaked: %s",secret)}
	}
	if report.Endpoints[0].Method!="GET"||report.Endpoints[0].Requests!=2{
		t.Fatalf("wrong endpoint grouping: %+v",report.Endpoints)
	}
}
func StringFixture()string{
	return `{"log":{"entries":[
		{"request":{"url":"https://example.test/invoices/123?api_key=my-private-query","method":"GET","headers":[{"name":"Authorization","value":"Bearer secret-session-token"}]},"response":{"status":200,"content":{"text":"sensitive response"}}},
		{"request":{"url":"https://example.test/invoices/123?other=value","method":"GET","headers":[{"name":"Cookie","value":"session=cookie-secret"}]},"response":{"status":403}},
		{"request":{"url":"https://elsewhere.test/invoices/123","method":"GET"},"response":{"status":200}},
		{"request":{"url":"https://user:password@example.test/hidden","method":"GET"},"response":{"status":200}}
	]}}`
}
func TestInvalidHARAndOrigin(t *testing.T){
	if _,err:=Analyze(strings.NewReader("{}"),[]string{"https://example.test/a"});err==nil{t.Fatal("path-bearing origin accepted")}
	if _,err:=Analyze(strings.NewReader("{"),[]string{"https://example.test"});err==nil{t.Fatal("invalid JSON accepted")}
	if _,err:=Analyze(strings.NewReader(strings.Repeat(" ",MaxFileBytes+1)),[]string{"https://example.test"});err==nil{t.Fatal("oversized HAR accepted")}
	if _,err:=Analyze(strings.NewReader("{}"),nil);err==nil{t.Fatal("missing scope accepted")}
}
func TestDistinctMethodsAreNotConflated(t *testing.T){
	payload:=`{"log":{"entries":[
		{"request":{"url":"https://example.test/api/item?token=x","method":"GET"},"response":{"status":200}},
		{"request":{"url":"https://example.test/api/item?token=y","method":"POST"},"response":{"status":201}},
		{"request":{"url":"https://example.test/api/item","method":"INVALID METHOD"},"response":{"status":500}}
	]}}`
	s,err:=Analyze(strings.NewReader(payload),[]string{"https://example.test"})
	if err!=nil||s.UniqueEndpoints!=2||s.Invalid!=1||s.InScope!=2{t.Fatalf("bad method classification: %+v %v",s,err)}
}
