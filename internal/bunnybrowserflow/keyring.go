package bunnybrowserflow

import (
 "context"
 "errors"
 "strings"

 "github.com/zalando/go-keyring"
)

const KeyringService="BunnyMind-ApprovedBrowser"
// KeyringSecrets retrieves a pre-provisioned operator-owned test account
// value from the OS credential store. It is never returned to model-facing
// tools, persisted in evidence, or copied into the JSON plan.
type KeyringSecrets struct{}
func ValidSecretRef(actor,key string)bool{
 return validActor.MatchString(actor)&&validKey.MatchString(key)
}
func (KeyringSecrets) Resolve(ctx context.Context,actor,key string)(string,error){
 if err:=ctx.Err();err!=nil{return "",err}
 if !ValidSecretRef(actor,key){return "",errors.New("invalid test-persona secret reference")}
 value,err:=keyring.Get(KeyringService,actor+"/"+key)
 if err!=nil||len(value)==0||len(value)>256||strings.ContainsAny(value,"\r\n"){
  return "",errors.New("trusted test-account secret not available")
 }
 return value,nil
}
// SetApprovedSecret is called only by trusted local operator CLI code, not by
// an LLM-exposed tool. The caller obtains the value interactively.
func SetApprovedSecret(actor,key,value string)error{
 if !ValidSecretRef(actor,key)||len(value)==0||len(value)>256||strings.ContainsAny(value,"\r\n"){
  return errors.New("invalid secret or alias")
 }
 return keyring.Set(KeyringService,actor+"/"+key,value)
}
