package bunnyevidence

import (
	"encoding/json"
	"strings"
	"testing"
)
func example() Submission {
	return Submission{FindingID:"F-001",Marker:"PROOF-12345",Observations:[]Observation{
		{SampleID:"positive-1",Kind:"positive",Method:"GET",RequestURL:"http://127.0.0.1:8765/item/1",ResponseStatus:200,ResponseBody:"found PROOF-12345"},
		{SampleID:"control-1",Kind:"control",Method:"GET",RequestURL:"http://127.0.0.1:8765/item/1",ResponseStatus:403,ResponseBody:"denied"},
		{SampleID:"positive-2",Kind:"positive",Method:"GET",RequestURL:"http://127.0.0.1:8765/item/1",ResponseStatus:200,ResponseBody:"found PROOF-12345"},
		{SampleID:"control-2",Kind:"control",Method:"GET",RequestURL:"http://127.0.0.1:8765/item/1",ResponseStatus:403,ResponseBody:"denied"},
	}}
}
func TestConsistentSamples(t *testing.T){
	r,err:=Review(example());if err!=nil{t.Fatal(err)}
	if r.Assessment!="consistent-provided-observations"||r.PositiveSamples!=2||r.ControlSamples!=2{t.Fatalf("%+v",r)}
}
func TestMissingControls(t *testing.T){
	s:=example();s.Observations=s.Observations[:1]
	r,err:=Review(s);if err!=nil{t.Fatal(err)}
	if r.Assessment!="inconclusive"{t.Fatal("unsupported claim accepted")}
}
func TestContradictoryControl(t *testing.T){
	s:=example();s.Observations[1].ResponseBody="PROOF-12345"
	r,err:=Review(s);if err!=nil{t.Fatal(err)}
	if r.Assessment!="inconclusive"{t.Fatal("control contains marker")}
}
func TestReflectedMarker(t *testing.T){
	s:=example();s.Observations[0].RequestBody="PROOF-12345"
	r,err:=Review(s);if err!=nil{t.Fatal(err)}
	if r.Assessment!="inconclusive"{t.Fatal("request reflection accepted")}
}
func TestEncodedReflectedMarker(t *testing.T){
	s:=example();s.Observations[0].RequestURL+="?q=PROOF%2D12345"
	r,err:=Review(s);if err!=nil{t.Fatal(err)}
	if r.Assessment!="inconclusive"{t.Fatal("url reflection accepted")}
}
func TestDifferentOrigins(t *testing.T){
	s:=example();s.Observations[1].RequestURL="http://127.0.0.1:9876/"
	if _,err:=Review(s);err==nil{t.Fatal("cross-host control accepted")}
}
func TestDuplicateIDs(t *testing.T){
	s:=example();s.Observations[1].SampleID="positive-1"
	if _,err:=Review(s);err==nil{t.Fatal("duplicate sample accepted")}
}
func TestInvalidMarker(t *testing.T){
	s:=example();s.Marker="abc"
	if _,err:=Review(s);err==nil{t.Fatal("short marker accepted")}
}
func TestNoBodyOrSecretInResult(t *testing.T){
	s:=example();s.Observations[0].ResponseBody+="\nAuthorization: Bearer SENSITIVE_EXAMPLE_TOKEN"
	s.Observations[0].RequestURL+="?token=SECRET_QUERY_EXAMPLE"
	r,err:=Review(s);if err!=nil{t.Fatal(err)}
	b,err:=json.Marshal(r);if err!=nil{t.Fatal(err)}
	for _,secret:=range []string{"SENSITIVE_EXAMPLE_TOKEN","SECRET_QUERY_EXAMPLE","found PROOF-12345"}{
		if strings.Contains(string(b),secret){t.Fatalf("sensitive content emitted: %q",secret)}
	}
}
func TestBodyLimit(t *testing.T){
	s:=example();s.Observations[0].ResponseBody=strings.Repeat("A",131073)
	if _,err:=Review(s);err==nil{t.Fatal("overlarge response accepted")}
}
