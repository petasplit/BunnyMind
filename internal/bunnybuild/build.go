// Package bunnybuild binds lab run IDs to a signed measurement of a local
// file's bytes. A file hash does NOT prove any server executed that file.
package bunnybuild

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "time"
)

const MaxArtifactBytes int64 = 64 << 20
var safeID=regexp.MustCompile(`^[A-Za-z0-9_-]{1,96}$`)
var digestPattern=regexp.MustCompile(`^[0-9a-f]{64}$`)
type Record struct{
 Version int `json:"version"`
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 ArtifactSHA256 string `json:"artifact_sha256"`
 ArtifactBytes int64 `json:"artifact_bytes"`
 RecordedAt string `json:"recorded_at"`
}
type Signed struct{
 Record Record `json:"record"`
 Signature string `json:"signature"`
}
func (r Record) Validate()error{
 if r.Version!=1{return errors.New("unsupported build evidence version")}
 if !safeID.MatchString(r.EngagementID)||!safeID.MatchString(r.RunID){return errors.New("invalid engagement or run ID")}
 if !digestPattern.MatchString(r.ArtifactSHA256){return errors.New("artifact SHA256 must be 64 lowercase hex characters")}
 if r.ArtifactBytes<1||r.ArtifactBytes>MaxArtifactBytes{return errors.New("artifact byte count out of bounds")}
 if _,err:=time.Parse(time.RFC3339Nano,r.RecordedAt);err!=nil{return errors.New("invalid build evidence timestamp")}
 return nil
}
// MeasureAndSign accepts only a small regular file on the recorder's local
// disk, hashes the bytes actually read, and signs the result. It does not
// resolve any URL, inspect a network service, or execute the measured file.
// The caller must isolate the signing key and ensure the file is trustworthy.
func MeasureAndSign(path,engagement,run string,private ed25519.PrivateKey)(Signed,error){
 if len(private)!=ed25519.PrivateKeySize{return Signed{},errors.New("invalid signing private key")}
 if !filepath.IsAbs(path){return Signed{},errors.New("file path must be absolute")}
 info,err:=os.Lstat(path)
 if err!=nil{return Signed{},err}
 if !info.Mode().IsRegular(){return Signed{},errors.New("artifact must be a regular non-symlink file")}
 if info.Size()<1||info.Size()>MaxArtifactBytes{return Signed{},errors.New("artifact size out of bounds")}
 f,err:=os.Open(path)
 if err!=nil{return Signed{},err}
 defer f.Close()
 opened,err:=f.Stat()
 if err!=nil{return Signed{},err}
 if !opened.Mode().IsRegular()||!os.SameFile(info,opened){return Signed{},errors.New("artifact replaced between checks")}
 h:=sha256.New()
 n,err:=io.Copy(h,io.LimitReader(f,MaxArtifactBytes+1))
 if err!=nil{return Signed{},err}
 after,err:=f.Stat()
 if err!=nil{return Signed{},err}
 if n!=opened.Size()||n!=after.Size()||!opened.ModTime().Equal(after.ModTime())||n>MaxArtifactBytes{
  return Signed{},errors.New("artifact changed during measurement")
 }
 r:=Record{Version:1,EngagementID:engagement,RunID:run,
  ArtifactSHA256:hex.EncodeToString(h.Sum(nil)),ArtifactBytes:n,
  RecordedAt:time.Now().UTC().Format(time.RFC3339Nano)}
 if err:=r.Validate();err!=nil{return Signed{},err}
 payload,err:=json.Marshal(r)
 if err!=nil{return Signed{},err}
 return Signed{Record:r,Signature:base64.StdEncoding.EncodeToString(ed25519.Sign(private,payload))},nil
}
// Verify accepts only the pinned recorder public key. It returns the
// measured file fingerprint, not a live deployment or build attestation.
func Verify(pub ed25519.PublicKey,s Signed)(Record,error){
 if len(pub)!=ed25519.PublicKeySize{return Record{},errors.New("invalid public key")}
 if err:=s.Record.Validate();err!=nil{return Record{},err}
 sig,err:=base64.StdEncoding.Strict().DecodeString(s.Signature)
 if err!=nil||len(sig)!=ed25519.SignatureSize{return Record{},errors.New("invalid Ed25519 signature encoding")}
 payload,err:=json.Marshal(s.Record)
 if err!=nil{return Record{},err}
 if !ed25519.Verify(pub,payload,sig){return Record{},fmt.Errorf("build evidence signature mismatch")}
 return s.Record,nil
}
