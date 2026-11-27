package bunnybrowserflow

import (
 "context"
 "errors"
 "strings"
 "testing"
 "time"
)

func TestRFC6238EnrolledTOTP(t *testing.T) {
 // RFC 6238 SHA1 test vector, truncated to six decimal digits.
 for _,tc:=range []struct{at int64;want string}{
  {59,"287082"},{1111111109,"081804"},{1111111111,"050471"},
  {1234567890,"005924"},{2000000000,"279037"},{20000000000,"353130"},
 }{
  got,err:=TOTPAt("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",time.Unix(tc.at,0))
  if err!=nil||got!=tc.want{t.Fatalf("TOTP %d: %q want %q: %v",tc.at,got,tc.want,err)}
 }
}
func TestEnrolledTOTPRejectsBadSeedsAndMissingOwnership(t *testing.T){
 for _,seed:=range []string{"","ABC","not-base32-%%"}{
  if _,err:=TOTPAt(seed,time.Unix(59,0));err==nil{t.Fatalf("accepted invalid seed %q",seed)}
 }
 p:=OwnedTOTP{Secrets:testFactorSecrets{ok:false}}
 if err:=p.Arm(context.Background(),"owner");err==nil{t.Fatal("unenrolled identity accepted")}
 p=OwnedTOTP{Secrets:testFactorSecrets{ok:true},Now:func()time.Time{return time.Unix(59,0)}}
 if err:=p.Arm(context.Background(),"owner");err!=nil{t.Fatal(err)}
 // Fixed vectors use t=59 (remaining one second), so Wait would sleep;
 // test generation directly above and provider with a fresh time step here.
 p.Now=func()time.Time{return time.Unix(65,0)}
 v,err:=p.Wait(context.Background(),"owner")
 if err!=nil||len(v)!=6||strings.Contains(v," "){t.Fatalf("invalid factor: %q %v",v,err)}
}
type testFactorSecrets struct{ok bool}
func (s testFactorSecrets) Resolve(ctx context.Context,actor,key string)(string,error){
 if !s.ok||actor!="owner"||key!="totp_seed"{return "",errors.New("no registered test account seed")}
 return "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",nil
}
