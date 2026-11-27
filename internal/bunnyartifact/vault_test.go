package bunnyartifact

import (
 "bytes"
 "crypto/rand"
 "os"
 "path/filepath"
 "testing"
)
func TestEncryptedRawProofAndScreenshotRoundTrip(t *testing.T){
 key:=make([]byte,32);_,_=rand.Read(key)
 dir:=t.TempDir()
 for _,tc:=range []struct{name,kind string;data []byte}{
  {"trace","http_proof",[]byte("Authorization: Bearer SECRET\r\n\r\nprivate-record")},
  {"otp-view","screenshot",[]byte{137,80,78,71,1,2,3,4}},
 }{
  receipt,err:=Store(dir,tc.name,tc.kind,tc.data,key)
  if err!=nil{t.Fatal(err)}
  if receipt.SHA256==""||receipt.Bytes!=len(tc.data){t.Fatalf("missing integrity %v",receipt)}
  encrypted,err:=os.ReadFile(filepath.Join(dir,receipt.File))
  if err!=nil{t.Fatal(err)}
  if bytes.Contains(encrypted,tc.data){t.Fatal("raw private evidence present in ciphertext")}
  reopened,err:=Open(dir,tc.name,tc.kind,key)
  if err!=nil||!bytes.Equal(reopened,tc.data){t.Fatalf("failed authorized decryption: %v",err)}
  altered:=append([]byte(nil),key...);altered[0]^=1
  if _,err:=Open(dir,tc.name,tc.kind,altered);err==nil{t.Fatal("incorrect encryption key accepted")}
 }
}
func TestArtifactNamesCannotEscapeVault(t *testing.T){
 key:=make([]byte,32);_,_=rand.Read(key)
 for _,name:=range []string{"../outside","bad/secret","..","password:raw",""}{
  if _,err:=Store(t.TempDir(),name,"screenshot",[]byte("private"),key);err==nil{
   t.Fatalf("unsafe evidence artifact name %q",name)
  }
 }
}
