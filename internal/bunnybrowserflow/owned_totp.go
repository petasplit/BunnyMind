package bunnybrowserflow

import (
 "context"
 "crypto/hmac"
 "crypto/sha1"
 "encoding/base32"
 "encoding/binary"
 "errors"
 "fmt"
 "strings"
 "time"
)

// OwnedTOTP generates RFC 6238 codes for an operator-enrolled test account.
// The base32 seed is in the OS credential store under actor:totp_seed.
// It does not enroll a factor or defeat MFA on any other account.
type OwnedTOTP struct {
 Secrets Secrets
 Now func() time.Time
}

func TOTPAt(seed string, at time.Time) (string,error) {
 clean:=strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(seed)," ",""))
 if len(clean)<16||len(clean)>256 {return "",errors.New("invalid enrolled TOTP seed")}
 key,err:=base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(clean,"="))
 if err!=nil||len(key)<10{return "",errors.New("enrolled TOTP seed is malformed")}
 if at.Unix()<0{return "",errors.New("TOTP time before Unix epoch")}
 counter:=uint64(at.Unix()/30)
 var message [8]byte
 binary.BigEndian.PutUint64(message[:],counter)
 h:=hmac.New(sha1.New,key)
 _,_=h.Write(message[:])
 digest:=h.Sum(nil)
 offset:=digest[len(digest)-1]&0x0f
 code:=(binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000
 return fmt.Sprintf("%06d",code),nil
}
func (p OwnedTOTP) Arm(ctx context.Context,actor string)error {
 if p.Secrets==nil||!validActor.MatchString(actor){return errors.New("trusted TOTP identity required")}
 _,err:=p.Secrets.Resolve(ctx,actor,"totp_seed")
 if err!=nil{return errors.New("approved account has no enrolled TOTP seed")}
 return nil
}
func (p OwnedTOTP) Wait(ctx context.Context,actor string)(string,error) {
 if p.Secrets==nil||!validActor.MatchString(actor){return "",errors.New("trusted TOTP identity required")}
 seed,err:=p.Secrets.Resolve(ctx,actor,"totp_seed")
 if err!=nil{return "",errors.New("approved TOTP seed unavailable")}
 now:=time.Now().UTC()
 if p.Now!=nil{now=p.Now().UTC()}
 // Avoid submitting codes with less than three seconds of validity.
 remaining:=30-(now.Unix()%30)
 if remaining<=3 {
  select{
  case <-ctx.Done():return "",ctx.Err()
  case <-time.After(time.Duration(remaining+1)*time.Second):
  }
  now=time.Now().UTC()
  if p.Now!=nil{now=p.Now().UTC()}
 }
 return TOTPAt(seed,now)
}
