// bunnyreceipt-recorder is a standalone offline utility for controlled labs.
// Keep its private key outside the Antares workspace and CI artifacts.
package main

import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "path/filepath"
 "runtime"
 "strings"

 "github.com/enowdev/antares/internal/bunnyreceipt"
)
func fail(err error){fmt.Fprintln(os.Stderr,err);os.Exit(1)}
func writeNew(path string,data []byte,mode os.FileMode)error{
 if !filepath.IsAbs(path){return errors.New("output path must be absolute")}
 f,err:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,mode)
 if err!=nil{return err}
 if _,err=f.Write(data);err!=nil{f.Close();_ = os.Remove(path);return err}
 if err=f.Sync();err!=nil{f.Close();_ = os.Remove(path);return err}
 if err=f.Close();err!=nil{_ = os.Remove(path);return err}
 return nil
}
func main(){
 action:=flag.String("action","","keygen or sign")
 private:=flag.String("private","","absolute path to isolated lab private key")
 public:=flag.String("public","","absolute path for public verifier key (keygen only)")
 input:=flag.String("input","","absolute JSON observation file (sign only)")
 output:=flag.String("output","","absolute output receipt JSON (sign only)")
 flag.Parse()
 switch *action{
 case "keygen":
  if *private==""||*public==""||*private==*public{fail(errors.New("separate absolute private and public output paths required"))}
  pub,priv,err:=bunnyreceipt.Keypair();if err!=nil{fail(err)}
  if err=writeNew(*private,[]byte(base64.StdEncoding.EncodeToString(priv)+"\n"),0600);err!=nil{fail(err)}
  if err=writeNew(*public,[]byte(base64.StdEncoding.EncodeToString(pub)+"\n"),0644);err!=nil{
   _=os.Remove(*private);fail(err)
  }
  fmt.Println("Created lab signing key and verifier public key at requested paths. Do not copy private key into Antares, GitHub, or an agent workspace.")
 case "sign":
  if *private==""||*input==""||*output==""||!filepath.IsAbs(*private)||!filepath.IsAbs(*input){fail(errors.New("absolute private key, input and output paths required"))}
  info,err:=os.Stat(*private);if err!=nil{fail(err)}
  if runtime.GOOS!="windows"&&info.Mode().Perm()&0077!=0{fail(errors.New("private key file must be owner-only (0600)"))}
  blob,err:=os.ReadFile(*private);if err!=nil{fail(err)}
  secret,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(blob)))
  if err!=nil||len(secret)!=ed25519.PrivateKeySize{fail(errors.New("private key is malformed"))}
  raw,err:=os.ReadFile(*input);if err!=nil{fail(err)}
  var obs bunnyreceipt.Observation
  d:=json.NewDecoder(strings.NewReader(string(raw)));d.DisallowUnknownFields()
  if err=d.Decode(&obs);err!=nil{fail(err)}
  result,err:=bunnyreceipt.Sign(ed25519.PrivateKey(secret),obs);if err!=nil{fail(err)}
  encoded,err:=json.MarshalIndent(result,"","  ");if err!=nil{fail(err)}
  if err=writeNew(*output,append(encoded,'\n'),0600);err!=nil{fail(err)}
  fmt.Println("Signed one offline lab observation to the requested file.")
 default:
  fmt.Fprintln(os.Stderr,"usage: bunnyreceipt-recorder -action keygen -private /abs/key -public /abs/pub | -action sign -private /abs/key -input /abs/observation.json -output /abs/receipt.json")
  os.Exit(2)
 }
}
