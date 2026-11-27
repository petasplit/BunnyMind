package bunnyartifact

import (
 "crypto/rand"
 "encoding/hex"
 "errors"

 "github.com/zalando/go-keyring"
)

const service="BunnyMind-Evidence"
const keyName="local-aes256"
// InitKey creates a private encryption key in the operating system credential
// store. Existing keys are never silently replaced (that would orphan proofs).
func InitKey()error {
 if _,err:=keyring.Get(service,keyName);err==nil{return errors.New("evidence key already exists")}
 b:=make([]byte,32)
 if _,err:=rand.Read(b);err!=nil{return err}
 return keyring.Set(service,keyName,hex.EncodeToString(b))
}
func ReadKey()([]byte,error){
 raw,err:=keyring.Get(service,keyName)
 if err!=nil{return nil,errors.New("BunnyMind evidence key not enrolled in OS credential store")}
 key,err:=hex.DecodeString(raw)
 if err!=nil||len(key)!=32{return nil,errors.New("invalid evidence key format")}
 return key,nil
}
