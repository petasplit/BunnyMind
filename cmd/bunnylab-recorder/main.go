// bunnylab-recorder is a standalone capture-and-sign utility for explicitly
// started local test fixtures. Never give its private key to the AI agent.
package main

import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "runtime"
 "strings"

 "github.com/enowdev/antares/internal/bunnylab"
)
func fail(err error){fmt.Fprintln(os.Stderr,err);os.Exit(1)}
func main(){
 input:=flag.String("plan","","absolute path to local fixture request plan JSON")
 private:=flag.String("private","","absolute path to isolated Ed25519 private key")
 output:=flag.String("output","","absolute path for signed receipt bundle (must not exist)")
 flag.Parse()
 if *input==""||*private==""||*output==""||!filepath.IsAbs(*input)||!filepath.IsAbs(*private)||!filepath.IsAbs(*output){
  fail(errors.New("plan, private, output must all be absolute paths"))
 }
 if *input==*private||*private==*output||*input==*output{
  fail(errors.New("input, output and private key paths must be distinct"))
 }
 info,err:=os.Stat(*private);if err!=nil{fail(err)}
 if runtime.GOOS!="windows"&&info.Mode().Perm()&0077!=0{fail(errors.New("private signing key must be owner-only (0600)"))}
 data,err:=os.ReadFile(*private);if err!=nil{fail(err)}
 secret,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
 if err!=nil||len(secret)!=ed25519.PrivateKeySize{fail(errors.New("invalid signing key"))}
 b,err:=os.ReadFile(*input);if err!=nil{fail(err)}
 if len(b)>65536{fail(errors.New("plan exceeds 64KiB"))}
 dec:=json.NewDecoder(strings.NewReader(string(b)));dec.DisallowUnknownFields()
 var plan bunnylab.Plan
 if err=dec.Decode(&plan);err!=nil{fail(err)}
 var trailing any
 if err=dec.Decode(&trailing);err!=io.EOF{fail(errors.New("plan must contain exactly one JSON value"))}
 bundle,err:=bunnylab.Capture(context.Background(),plan,ed25519.PrivateKey(secret))
 if err!=nil{fail(err)}
 result,err:=json.MarshalIndent(bundle,"","  ");if err!=nil{fail(err)}
 f,err:=os.OpenFile(*output,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{fail(err)}
 if _,err=f.Write(append(result,'\n'));err!=nil{f.Close();_ = os.Remove(*output);fail(err)}
 if err=f.Sync();err!=nil{f.Close();_ = os.Remove(*output);fail(err)}
 if err=f.Close();err!=nil{_ = os.Remove(*output);fail(err)}
 fmt.Printf("Captured and signed %d local observations. Receipt bundle saved at the requested path.\n",len(bundle.Receipts))
}
