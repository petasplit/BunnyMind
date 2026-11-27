// Package bunnyartifact stores raw security evidence in an authenticated,
// encrypted local vault. The separate manifest contains nonsecret hashes only.
package bunnyartifact

import (
 "crypto/aes"
 "crypto/cipher"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "time"
)

var artifactName=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}$`)
type Receipt struct {
 File string `json:"file"`
 Kind string `json:"kind"`
 SHA256 string `json:"sha256"`
 Bytes int `json:"bytes"`
 CreatedAt string `json:"created_at"`
}
type envelope struct {
 Version int `json:"version"`
 Nonce string `json:"nonce"`
 Ciphertext string `json:"ciphertext"`
}
// Store creates an AES-256-GCM file with fresh random nonce. The key must be
// owned by a trusted local credential provider; never pass it to a model tool.
func Store(dir,name,kind string,data,key []byte)(Receipt,error){
 if !artifactName.MatchString(name)||strings.Contains(name,"..")||len(key)!=32{
  return Receipt{},errors.New("invalid artifact name or encryption key")
 }
 if len(data)==0||len(data)>4*1024*1024{return Receipt{},errors.New("artifact must be 1 byte..4 MiB")}
 if kind==""||len(kind)>40{return Receipt{},errors.New("invalid artifact type")}
 block,err:=aes.NewCipher(key)
 if err!=nil{return Receipt{},err}
 gcm,err:=cipher.NewGCM(block)
 if err!=nil{return Receipt{},err}
 nonce:=make([]byte,gcm.NonceSize())
 if _,err:=rand.Read(nonce);err!=nil{return Receipt{},err}
 ciphertext:=gcm.Seal(nil,nonce,data,[]byte(name+"|"+kind))
 item:=envelope{Version:1,Nonce:hex.EncodeToString(nonce),Ciphertext:hex.EncodeToString(ciphertext)}
 encoded,err:=json.Marshal(item)
 if err!=nil{return Receipt{},err}
 if err:=os.MkdirAll(dir,0700);err!=nil{return Receipt{},err}
 path:=filepath.Join(dir,name+".enc")
 fd,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return Receipt{},err}
 if _,err:=fd.Write(encoded);err!=nil{fd.Close();os.Remove(path);return Receipt{},err}
 if err:=fd.Sync();err!=nil{fd.Close();return Receipt{},err}
 if err:=fd.Close();err!=nil{return Receipt{},err}
 h:=sha256.Sum256(data)
 return Receipt{File:filepath.Base(path),Kind:kind,SHA256:hex.EncodeToString(h[:]),
  Bytes:len(data),CreatedAt:time.Now().UTC().Format(time.RFC3339Nano)},nil
}
// Open returns decrypted content only to a trusted local process; a separate
// explicit export command can write it back under restrictive permissions.
func Open(dir,name,kind string,key []byte)([]byte,error){
 if !artifactName.MatchString(name)||strings.Contains(name,"..")||len(key)!=32{
  return nil,errors.New("invalid artifact name or key")
 }
 raw,err:=os.ReadFile(filepath.Join(dir,name+".enc"))
 if err!=nil{return nil,err}
 if len(raw)>9*1024*1024{return nil,errors.New("encrypted artifact exceeds expected bound")}
 var e envelope
 if json.Unmarshal(raw,&e)!=nil||e.Version!=1{return nil,errors.New("invalid evidence envelope")}
 nonce,err:=hex.DecodeString(e.Nonce)
 if err!=nil{return nil,err}
 blob,err:=hex.DecodeString(e.Ciphertext)
 if err!=nil{return nil,err}
 block,err:=aes.NewCipher(key)
 if err!=nil{return nil,err}
 gcm,err:=cipher.NewGCM(block)
 if err!=nil{return nil,err}
 if len(nonce)!=gcm.NonceSize(){return nil,errors.New("invalid nonce length")}
 result,err:=gcm.Open(nil,nonce,blob,[]byte(name+"|"+kind))
 if err!=nil{return nil,fmt.Errorf("evidence integrity failure: %w",err)}
 return result,nil
}
