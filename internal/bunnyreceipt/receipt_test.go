package bunnyreceipt

import (
 "crypto/ed25519"
 "encoding/json"
 "strings"
 "testing"
)
func example(id string,kind string,positive bool)Observation{
 return Observation{Version:1,EngagementID:"local_lab",RunID:"run_1",CaseID:"fixture_1",SampleID:id,Kind:kind,
 Method:"GET",Origin:"http://127.0.0.1:8765",RequestSHA256:Dig("request:"+id),
 ResponseSHA256:Dig("response:"+id),MarkerSHA256:Dig("synthetic-marker"),ResponseStatus:200,
 MarkerPresent:positive,RecordedAt:"2026-11-27T09:45:00Z"}
}
func fixture(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey,Bundle){
 t.Helper();pub,priv,err:=Keypair();if err!=nil{t.Fatal(err)}
 b:=Bundle{EngagementID:"local_lab",RunID:"run_1",CaseID:"fixture_1"}
 for _,v:=range []Observation{example("p1","positive",true),example("p2","positive",true),example("c1","control",false),example("c2","control",false)}{
  signed,err:=Sign(priv,v);if err!=nil{t.Fatal(err)}
  b.Receipts=append(b.Receipts,signed)
 }
 return pub,priv,b
}
func TestValidSignedEvidence(t *testing.T){
 pub,_,b:=fixture(t)
 out,err:=Verify(pub,b)
 if err!=nil||out.Assessment!="consistent-signed-observations"||out.AuthenticatedReceipts!=4{
  t.Fatalf("%+v %v",out,err)
 }
}
func TestTamperedMetadataRejected(t *testing.T){
 pub,_,b:=fixture(t)
 b.Receipts[0].Observation.MarkerPresent=false
 if _,err:=Verify(pub,b);err==nil{t.Fatal("tamper accepted")}
}
func TestWrongSignerRejected(t *testing.T){
 _,_,b:=fixture(t)
 other,_,_:=Keypair()
 if _,err:=Verify(other,b);err==nil{t.Fatal("wrong key accepted")}
}
func TestDuplicateSampleRejected(t *testing.T){
 pub,priv,b:=fixture(t)
 r,_:=Sign(priv,example("p1","positive",true));b.Receipts[1]=r
 if _,err:=Verify(pub,b);err==nil{t.Fatal("duplicate accepted")}
}
func TestCrossEngagementRejected(t *testing.T){
 pub,_,b:=fixture(t)
 b.EngagementID="another_lab"
 if _,err:=Verify(pub,b);err==nil{t.Fatal("engagement swap accepted")}
}
func TestMissingControlIsInconclusive(t *testing.T){
 pub,_,b:=fixture(t);b.Receipts=b.Receipts[:2]
 out,err:=Verify(pub,b)
 if err!=nil||out.Assessment!="inconclusive"{t.Fatalf("%+v %v",out,err)}
}
func TestContradictoryControl(t *testing.T){
 pub,priv,b:=fixture(t)
 changed:=example("c1","control",true)
 b.Receipts[2],_=Sign(priv,changed)
 out,err:=Verify(pub,b)
 if err!=nil||out.Assessment!="inconclusive"{t.Fatalf("%+v %v",out,err)}
}
func TestReflectionIsInconclusive(t *testing.T){
 pub,priv,b:=fixture(t)
 changed:=example("p1","positive",true);changed.MarkerInRequest=true
 b.Receipts[0],_=Sign(priv,changed)
 out,err:=Verify(pub,b)
 if err!=nil||out.Assessment!="inconclusive"{t.Fatalf("%+v %v",out,err)}
}
func TestNoRawBodyOrSecretsReturned(t *testing.T){
 pub,_,b:=fixture(t)
 out,err:=Verify(pub,b);if err!=nil{t.Fatal(err)}
 raw,_:=json.Marshal(out)
 if strings.Contains(string(raw),"synthetic-marker")||strings.Contains(string(raw),"127.0.0.1:8765"){t.Fatal("raw marker/origin leaked")}
}
func TestNoMalformedOriginOrDigest(t *testing.T){
 _,priv,_:=fixture(t)
 for _,origin:=range []string{"file:///etc/passwd","http://user:pass@host","https://example.test/path"}{
  o:=example("x","positive",true);o.Origin=origin
  if _,err:=Sign(priv,o);err==nil{t.Fatalf("allowed %s",origin)}
 }
 o:=example("x","positive",true);o.ResponseSHA256="bad"
 if _,err:=Sign(priv,o);err==nil{t.Fatal("invalid digest")}
}
func TestSignatureEncodingIsStrict(t *testing.T){
 pub,_,b:=fixture(t)
 b.Receipts[0].Signature="malformed"
 if _,err:=Verify(pub,b);err==nil{t.Fatal("bad signature accepted")}
}

func TestMixedSignedBuildHashesRejected(t *testing.T){
 pub,priv,b:=fixture(t)
 for i:=range b.Receipts{
  changed:=b.Receipts[i].Observation
  changed.BuildSHA256=strings.Repeat("a",64)
  if i==1{changed.BuildSHA256=strings.Repeat("b",64)}
  signed,err:=Sign(priv,changed)
  if err!=nil{t.Fatal(err)}
  b.Receipts[i]=signed
 }
 if _,err:=Verify(pub,b);err==nil{t.Fatal("signed bundle mixed multiple builds")}
}
func TestInvalidOptionalBuildHashRejected(t *testing.T){
 _,priv,_:=fixture(t)
 v:=example("sample","positive",true)
 v.BuildSHA256="not-a-sha256"
 if _,err:=Sign(priv,v);err==nil{t.Fatal("malformed build hash was accepted")}
}
