// bunnybench-signed scores controlled lab runs using Ed25519-signed receipts.
// It performs no scanning, inference or network requests.
package main
import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "strings"

 "github.com/enowdev/antares/internal/bunnybench"
)
func main(){
 input:=flag.String("input","","absolute or relative JSON signed study")
 pubPath:=flag.String("public","","pinned Ed25519 public-key file")
 output:=flag.String("output","","optional output JSON filename; default stdout")
 flag.Parse()
 if *input==""||*pubPath==""{fmt.Fprintln(os.Stderr,"usage: bunnybench-signed -input study.json -public recorder-public.key [-output results.json]");os.Exit(2)}
 data,err:=os.ReadFile(*input);if err!=nil{exit(err)}
 var study bunnybench.SignedStudy
 dec:=json.NewDecoder(strings.NewReader(string(data)));dec.DisallowUnknownFields()
 if err:=dec.Decode(&study);err!=nil{exit(err)}
 keydata,err:=os.ReadFile(*pubPath);if err!=nil{exit(err)}
 pub,err:=base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(keydata)))
 if err!=nil||len(pub)!=ed25519.PublicKeySize{exit(errors.New("invalid pinned public key"))}
 result,err:=bunnybench.ScoreSignedStudy(ed25519.PublicKey(pub),study)
 if err!=nil{exit(err)}
 encoded,err:=json.MarshalIndent(result,"","  ");if err!=nil{exit(err)}
 encoded=append(encoded,'\n')
 if *output!=""{if err=os.WriteFile(*output,encoded,0600);err!=nil{exit(err)}
 }else{fmt.Print(string(encoded))}
}
func exit(err error){fmt.Fprintln(os.Stderr,err);os.Exit(1)}
