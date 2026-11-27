// Package bunnyreceipt signs and verifies metadata captured by an isolated
// test recorder. A valid signature authenticates the recorder, not a bug.
package bunnyreceipt

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net/url"
 "regexp"
 "sort"
 "time"
)

const MaxReceipts=64
var id=regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`)
var sha=regexp.MustCompile(`^[0-9a-f]{64}$`)

type Observation struct {
 Version int `json:"version"`
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 CaseID string `json:"case_id"`
 SampleID string `json:"sample_id"`
 Kind string `json:"kind"`
 Actor string `json:"actor,omitempty"`
 Method string `json:"method"`
 Origin string `json:"origin"`
 RequestSHA256 string `json:"request_sha256"`
 ResponseSHA256 string `json:"response_sha256"`
 MarkerSHA256 string `json:"marker_sha256"`
 BuildSHA256 string `json:"build_sha256,omitempty"`
 ResponseStatus int `json:"response_status"`
 MarkerPresent bool `json:"marker_present"`
 MarkerInRequest bool `json:"marker_in_request"`
 RecordedAt string `json:"recorded_at"`
}
type Signed struct {
 Observation Observation `json:"observation"`
 Signature string `json:"signature"`
}
type Bundle struct {
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 CaseID string `json:"case_id"`
 Receipts []Signed `json:"receipts"`
}
type Summary struct {
 Assessment string `json:"assessment"`
 AuthenticatedReceipts int `json:"authenticated_receipts"`
 PositiveSamples int `json:"positive_samples"`
 ControlSamples int `json:"control_samples"`
 ReceiptsSHA256 []string `json:"receipt_sha256"`
 Reasons []string `json:"reasons"`
 Disclaimer string `json:"disclaimer"`
}
func Dig(s string)string{v:=sha256.Sum256([]byte(s));return hex.EncodeToString(v[:])}
func ValidObservation(o Observation)error{
 if o.Version!=1{return errors.New("unsupported observation version")}
 for _,v:=range []string{o.EngagementID,o.RunID,o.CaseID,o.SampleID}{
  if !id.MatchString(v){return errors.New("invalid engagement, run, case or sample ID")}
 }
 if o.Actor!="" && !id.MatchString(o.Actor){return errors.New("invalid observation actor")}
 if o.Kind!="positive"&&o.Kind!="control"{return errors.New("kind must be positive or control")}
 if o.Method!="GET"&&o.Method!="HEAD"&&o.Method!="POST"{return errors.New("unsupported request method")}
 u,err:=url.Parse(o.Origin)
 if err!=nil||u==nil||(u.Scheme!="http"&&u.Scheme!="https")||u.Opaque!=""||
  u.User!=nil||u.Hostname()==""||(u.Path!=""&&u.Path!="/")||u.RawQuery!=""||u.Fragment!=""{
  return errors.New("origin must be an absolute HTTP(S) origin without credentials")
 }
 if o.BuildSHA256!=""&&!sha.MatchString(o.BuildSHA256){return errors.New("optional build_sha256 must be a lowercase SHA256 digest")}
 for _,v:=range []string{o.RequestSHA256,o.ResponseSHA256,o.MarkerSHA256}{
  if !sha.MatchString(v){return errors.New("request, response and marker require SHA-256 digests")}
 }
 if o.ResponseStatus<100||o.ResponseStatus>599{return errors.New("invalid response status")}
 tm,err:=time.Parse(time.RFC3339Nano,o.RecordedAt)
 if err!=nil||tm.IsZero(){return errors.New("invalid timestamp")}
 return nil
}
func Keypair()(ed25519.PublicKey,ed25519.PrivateKey,error){return ed25519.GenerateKey(rand.Reader)}
func Sign(priv ed25519.PrivateKey,o Observation)(Signed,error){
 if len(priv)!=ed25519.PrivateKeySize{return Signed{},errors.New("invalid signer key")}
 if err:=ValidObservation(o);err!=nil{return Signed{},err}
 b,err:=json.Marshal(o);if err!=nil{return Signed{},err}
 return Signed{Observation:o,Signature:base64.StdEncoding.EncodeToString(ed25519.Sign(priv,b))},nil
}
func verifyOne(pub ed25519.PublicKey,s Signed)error{
 if len(pub)!=ed25519.PublicKeySize{return errors.New("invalid public key")}
 if err:=ValidObservation(s.Observation);err!=nil{return err}
 signature,err:=base64.StdEncoding.Strict().DecodeString(s.Signature)
 if err!=nil||len(signature)!=ed25519.SignatureSize{return errors.New("invalid signature encoding")}
 data,err:=json.Marshal(s.Observation);if err!=nil{return err}
 if !ed25519.Verify(pub,data,signature){return errors.New("signature mismatch")}
 return nil
}
// Verify authenticates a bundle from a trusted, separately operated recorder.
// Consistency is not independent replay or proof of vulnerability impact.
func Verify(pub ed25519.PublicKey,b Bundle)(Summary,error){
 out:=Summary{Assessment:"inconclusive",ReceiptsSHA256:[]string{},Reasons:[]string{},
 Disclaimer:"Cryptographic signatures only authenticate the configured recorder key. Marker flags are asserted by that recorder; this does not independently replay traffic, prove exploitation, or validate impact."}
 for _,value:=range []string{b.EngagementID,b.RunID,b.CaseID}{
  if !id.MatchString(value){return Summary{},errors.New("invalid bundle identifier")}
 }
 if len(b.Receipts)==0||len(b.Receipts)>MaxReceipts{return Summary{},fmt.Errorf("bundle needs 1..%d signed receipts",MaxReceipts)}
 seen:=map[string]bool{}
 var marker,origin string
 var build string
 seenBuild:=false
 var badPositive,controlPresent,reflected bool
 for _,r:=range b.Receipts{
  if err:=verifyOne(pub,r);err!=nil{return Summary{},fmt.Errorf("untrusted receipt: %w",err)}
  o:=r.Observation
  if o.EngagementID!=b.EngagementID||o.RunID!=b.RunID||o.CaseID!=b.CaseID{return Summary{},errors.New("cross-engagement or cross-run receipt")}
  if seen[o.SampleID]{return Summary{},errors.New("reused sample ID")}
  seen[o.SampleID]=true
  if marker==""{marker=o.MarkerSHA256}else if marker!=o.MarkerSHA256{return Summary{},errors.New("different proof indicator hashes")}
  if origin==""{origin=o.Origin}else if origin!=o.Origin{return Summary{},errors.New("mixed origins")}
  if !seenBuild{build=o.BuildSHA256;seenBuild=true}else if build!=o.BuildSHA256{return Summary{},errors.New("mixed artifact build fingerprints")}
  out.AuthenticatedReceipts++
  signedBytes,_:=json.Marshal(r)
  out.ReceiptsSHA256=append(out.ReceiptsSHA256,Dig(string(signedBytes)))
  if o.Kind=="positive"{
   out.PositiveSamples++
   if !o.MarkerPresent{badPositive=true}
   if o.MarkerInRequest{reflected=true}
  }else{
   out.ControlSamples++
   if o.MarkerPresent{controlPresent=true}
  }
 }
 if out.PositiveSamples<2{out.Reasons=append(out.Reasons,"need two independently captured positive samples")}
 if out.ControlSamples<2{out.Reasons=append(out.Reasons,"need two negative-control samples")}
 if badPositive{out.Reasons=append(out.Reasons,"a positive observation lacks the asserted indicator")}
 if controlPresent{out.Reasons=append(out.Reasons,"negative control contains the indicator")}
 if reflected{out.Reasons=append(out.Reasons,"indicator may have been reflected from a positive request")}
 if len(out.Reasons)==0{
  out.Assessment="consistent-signed-observations"
  out.Reasons=[]string{"two or more signed positives and controls have consistent assertions; reproduction and impact remain unverified"}
 }
 sort.Strings(out.ReceiptsSHA256)
 return out,nil
}
