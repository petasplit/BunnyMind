package agent

import (
 "encoding/json"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/llm"
)

func TestRecoverReadOnlyStructuredLocalModelCall(t *testing.T) {
 response:=&llm.Response{Content:`{"name":"web_fetch","arguments":{"url":"https://yeswehack.com/programs/example"}}`}
 ok:=recoverReadOnlyToolCall(response,func(name string)bool{return name=="web_fetch"})
 if !ok||response.Content!=""||len(response.ToolCalls)!=1||response.ToolCalls[0].Name!="web_fetch"{
  t.Fatalf("safe pseudo call not recognized: %+v",response)
 }
 var args map[string]any
 if err:=json.Unmarshal([]byte(response.ToolCalls[0].Arguments),&args);err!=nil{t.Fatal(err)}
 if args["url"]!="https://yeswehack.com/programs/example"{t.Fatal("arguments modified")}
 if response.ToolCalls[0].ID==""{t.Fatal("missing traceable call ID")}
}

func TestNeverRecoverUnsafeOrAmbiguousPseudoCalls(t *testing.T) {
 unsafe:=[]string{
  `{"name":"terminal","arguments":{"command":"whoami"}}`,
  `{"name":"http_request","arguments":{"method":"POST","url":"https://example.org"}}`,
  `{"name":"scoped_read","arguments":{"url":"https://example.org","method":"POST"}}`,
  `{"name":"web_fetch","arguments":"raw shell code"}`,
  `{"name":"web_fetch","arguments":[]}`,
  `{"name":"web_fetch","arguments":{"url":"https://example.org"},"unexpected":true}`,
  `{"name":"web_fetch","arguments":{"url":"https://example.org"}} and something else`,
  `Sorry, can't assist with that request.`,
  ```+`{"name":"web_fetch","arguments":{}}`+` more prose`,
 }
 for i,content:=range unsafe{
  response:=&llm.Response{Content:content}
  if recoverReadOnlyToolCall(response,func(string)bool{return true}) {
   t.Fatalf("unsafe pseudo-tool-call %d ran: %s",i,content)
  }
  if response.Content!=content||len(response.ToolCalls)!=0{
   t.Fatalf("unsafe input %d was mutated",i)
  }
 }
}
func TestPseudoCallRespectsAvailableToolset(t *testing.T) {
 response:=&llm.Response{Content:`{"name":"web_fetch","arguments":{"url":"https://example.org"}}`}
 if recoverReadOnlyToolCall(response,func(string)bool{return false}){
  t.Fatal("unavailable tool was recovered")
 }
 if !strings.Contains(response.Content,"web_fetch"){t.Fatal("unavailable JSON changed")}
}
