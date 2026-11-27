// bunnybuild-attest signs a measured local file for a controlled lab run.
// Run outside the Antares agent workspace with a separately protected key.
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

 "github.com/enowdev/antares/internal/bunnybuild"
)
func die(err error){fmt.Fprintln(os.Stderr,err);os.Exit(1)}
func main(){
 artifact:=flag.String("artifact","","absolute path to local build artifact file (max 64 MiB)")
 private:=flag.String("private","","absolute path to isolated Ed25519 private key")
 output:=flag.String("output","","absolute path to new signed measurement JSON")
 engagement:=flag.String("engagement","","explicit local test engagement ID")
 run:=flag.String("run","","test run identifier")
 flag.Parse()
 if *artifact==""||*private==""||*output==""||*engagement==""||*run==""||
  !filepath.IsAbs(*artifact)||!filepath.IsAbs(*private)||!filepath.IsAbs(*output){
  die(errors.New("absolute artifact/private/output paths and engagement/run IDs required"))
 }
 if *artifact==*private||*artifact==*output||*private==*output{
  die(errors.New("artifact, private key, and output must be distinct files"))
 }
 info,err:=os.Lstat(*private)
 if err!=nil{die(err)}
 if !info.Mode().IsRegular(){die(errors.New("signing private key must be a regular file"))}
 if runtime.GOOS!="windows"&&info.Mode().Perm()&0077!=0{
  die(errors.New("signing key must be owner-only (0600); on Windows use restrictive NTFS ACLs"))
 }
 keyfile,err:=os.ReadFile(*private);if err!=nil{die(err)}
 if len(keyfile)>2048{die(errors.New("private key file exceeds size limit"))}
 privateBytes,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(keyfile)))
 if err!=nil||len(privateBytes)!=ed25519.PrivateKeySize{die(errors.New("malformed Ed25519 private key"))}
 measured,err:=bunnybuild.MeasureAndSign(*artifact,*engagement,*run,ed25519.PrivateKey(privateBytes))
 if err!=nil{die(err)}
 payload,err:=json.MarshalIndent(measured,"","  ");if err!=nil{die(err)}
 f,err:=os.OpenFile(*output,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if err!=nil{die(err)}
 if _,err=f.Write(append(payload,'\n'));err!=nil{_ = f.Close();_ = os.Remove(*output);die(err)}
 if err=f.Sync();err!=nil{_ = f.Close();_ = os.Remove(*output);die(err)}
 if err=f.Close();err!=nil{_ = os.Remove(*output);die(err)}
 fmt.Println("Signed measured local artifact digest for the requested lab run.")
 fmt.Println("No deployment/server identity attestation was performed.")
}
