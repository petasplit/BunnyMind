package bunnybuild

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func prepare(t *testing.T,content string)(string,ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper()
 path:=filepath.Join(t.TempDir(),"synthetic-app.bin")
 if err:=os.WriteFile(path,[]byte(content),0600);err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 return path,pub,priv
}
func TestSignedMeasuredFile(t *testing.T){
 p,pub,priv:=prepare(t,"SYNTHETIC BEFORE BUILD")
 signed,err:=MeasureAndSign(p,"local_lab","run_before",priv)
 if err!=nil{t.Fatal(err)}
 result,err:=Verify(pub,signed)
 if err!=nil||result.ArtifactBytes!=int64(len("SYNTHETIC BEFORE BUILD")){t.Fatalf("%+v %v",result,err)}
 if result.ArtifactSHA256==""{t.Fatal("empty artifact digest")}
 blob,_:=json.Marshal(signed)
 if strings.Contains(string(blob),p){t.Fatal("local file path leaked in signed record")}
}
func TestDifferentFilesProduceDifferentHashes(t *testing.T){
 p,pub,priv:=prepare(t,"synthetic build v1")
 before,err:=MeasureAndSign(p,"lab","before",priv);if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(p,[]byte("synthetic build v2"),0600);err!=nil{t.Fatal(err)}
 after,err:=MeasureAndSign(p,"lab","after",priv);if err!=nil{t.Fatal(err)}
 if _,err:=Verify(pub,after);err!=nil{t.Fatal(err)}
 if before.Record.ArtifactSHA256==after.Record.ArtifactSHA256{t.Fatal("changed artifact has unchanged hash")}
}
func TestTamperedSignatureAndMetadataRejected(t *testing.T){
 p,pub,priv:=prepare(t,"synthetic binary")
 signed,err:=MeasureAndSign(p,"lab","run1",priv);if err!=nil{t.Fatal(err)}
 signed.Record.RunID="run2"
 if _,err:=Verify(pub,signed);err==nil{t.Fatal("tampered run accepted")}
}
func TestWrongSignerRejected(t *testing.T){
 p,_,priv:=prepare(t,"synthetic binary")
 signed,err:=MeasureAndSign(p,"lab","run1",priv);if err!=nil{t.Fatal(err)}
 wrong,_,_:=ed25519.GenerateKey(rand.Reader)
 if _,err:=Verify(wrong,signed);err==nil{t.Fatal("wrong signer accepted")}
}
func TestEmptyFileRejected(t *testing.T){
 p,_,priv:=prepare(t,"")
 if _,err:=MeasureAndSign(p,"lab","run1",priv);err==nil{t.Fatal("empty artifact accepted")}
}
func TestRelativePathRejected(t *testing.T){
 _,_,priv:=prepare(t,"synthetic binary")
 if _,err:=MeasureAndSign("artifact.bin","lab","run1",priv);err==nil{t.Fatal("relative file path accepted")}
}
func TestNoDirectoryAccepted(t *testing.T){
 _,_,priv:=prepare(t,"synthetic binary")
 if _,err:=MeasureAndSign(t.TempDir(),"lab","run1",priv);err==nil{t.Fatal("directory accepted")}
}
func TestSymlinkRejected(t *testing.T){
 p,_,priv:=prepare(t,"synthetic binary")
 link:=filepath.Join(t.TempDir(),"alias")
 if err:=os.Symlink(p,link);err!=nil{t.Skipf("symlink unsupported: %v",err)}
 if _,err:=MeasureAndSign(link,"lab","run1",priv);err==nil{t.Fatal("symlink accepted")}
}
func TestInvalidRecordRejected(t *testing.T){
 r:=Record{Version:1,EngagementID:"lab",RunID:"run",ArtifactSHA256:strings.Repeat("a",64),ArtifactBytes:2,RecordedAt:"2026-11-27T12:00:00Z"}
 if err:=r.Validate();err!=nil{t.Fatal(err)}
 r.ArtifactSHA256="invalid"
 if r.Validate()==nil{t.Fatal("bad digest accepted")}
}
func TestBoundedFileSize(t *testing.T){
 p,_,priv:=prepare(t,"small")
 f,err:=os.OpenFile(p,os.O_RDWR,0600);if err!=nil{t.Fatal(err)}
 if err=f.Truncate(MaxArtifactBytes+1);err!=nil{f.Close();t.Fatal(err)}
 _=f.Close()
 if _,err:=MeasureAndSign(p,"lab","run",priv);err==nil{t.Fatal("oversized artifact accepted")}
}
