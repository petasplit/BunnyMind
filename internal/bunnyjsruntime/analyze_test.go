package bunnyjsruntime

import (
 "strings"
 "testing"
)

func goodReport()Report{
 return Report{Version:1,Origin:"https://example.org",SourceSHA256:strings.Repeat("a",64),
  ASTNodesVisited:100,Endpoints:[]Endpoint{{
   Path:"/api/items",Method:"GET",Source:"ast_fetch",Line:1,Column:1,
   ReferenceSHA256:strings.Repeat("b",64),
  }},
 }
}
func TestValidateASTOutputAndScope(t *testing.T){
 p:=goodReport()
 if err:=Valid(p,p.Origin);err!=nil{t.Fatal(err)}
 p.Endpoints[0].Path="//offscope.example"
 if err:=Valid(p,p.Origin);err==nil{t.Fatal("protocol-relative URL accepted")}
 p=goodReport()
 p.Endpoints[0].Path="/api?token=private"
 if err:=Valid(p,p.Origin);err==nil{t.Fatal("query credentials appeared in parser output")}
 p=goodReport()
 p.Endpoints[0].Method="EXECUTE"
 if err:=Valid(p,p.Origin);err==nil{t.Fatal("arbitrary operation accepted")}
 p=goodReport()
 p.Origin="https://another.example"
 if err:=Valid(p,"https://example.org");err==nil{t.Fatal("unreviewed parser origin allowed")}
}
func TestASTOutputLimiter(t *testing.T){
 w:=limited{max:8}
 n,e:=w.Write([]byte("12345678"))
 if e!=nil||n!=8||w.overflow{t.Fatalf("exact byte cap failed: %d %v %v",n,e,w.overflow)}
 n,e=w.Write([]byte("EXTRA"))
 if e!=nil||n!=5||!w.overflow||w.data.String()!="12345678"{
  t.Fatalf("oversized helper output not rejected: %d %v",n,e)
 }
}
func TestNoBundledAnalyzerFailsClosed(t *testing.T){
 t.Setenv("BUNNY_JS_AST_BIN",t.TempDir()+"/missing")
 if _,err:=Analyze(t.Context(),"https://example.org","fetch('/api/items')");err==nil{
  t.Fatal("missing trusted parser binary silently pretended to run")
 }
}
