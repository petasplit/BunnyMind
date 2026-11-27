// Package bunnyidentity holds short-lived synthetic test-account sessions
// in an in-process memory vault. It never persists credentials or emails.
package bunnyidentity

import (
 "errors"
 "fmt"
 "regexp"
 "strings"
 "sync"
 "time"
)

const MaxIdentities = 8
const MaxLease = 30*time.Minute
const MinLease = 15*time.Second
var actorPattern=regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
type record struct {
 token []byte
 resource string
 expires time.Time
 generation uint64
}
type View struct {
 Actor string `json:"actor"`
 HasSession bool `json:"has_session"`
 ExpiresAt string `json:"expires_at,omitempty"`
 Generation uint64 `json:"generation"`
}
// Vault deliberately has only unexported storage fields: serializing the
// vault itself cannot expose the bearer tokens. Read-only views are redacted.
type Vault struct {
 mu sync.Mutex
 sessions map[string]*record
 now func()time.Time
 closed bool
}
func New()*Vault{return &Vault{sessions:map[string]*record{},now:time.Now}}
func valid(actor,token,resource string,ttl time.Duration)error{
 if !actorPattern.MatchString(actor){return errors.New("invalid synthetic identity alias")}
 if len(token)<32||len(token)>512||strings.ContainsAny(token," \t\r\n"){
  return errors.New("synthetic bearer token must be 32..512 non-whitespace characters")
 }
 if len(resource)<8||len(resource)>128||strings.ContainsAny(resource," \t\r\n/\\"){
  return errors.New("invalid synthetic resource reference")
 }
 if ttl<MinLease||ttl>MaxLease{return errors.New("session lease outside 15s..30m")}
 return nil
}
func wipe(b []byte){for i:=range b{b[i]=0}}
func (v *Vault) usedByOther(actor,token string)bool{
 now:=v.nowUTC()
 for name,r:=range v.sessions{
  if name!=actor&&now.Before(r.expires)&&equal(r.token,[]byte(token)){
   return true
  }
 }
 return false
}
func (v *Vault) nowUTC()time.Time{
 if v.now!=nil{return v.now().UTC()}
 return time.Now().UTC()
}
// Add creates one isolated identity. An existing active identity cannot be
// overwritten; rotation must be explicit and revokes the previous token.
func (v *Vault) Add(actor,token,resource string,ttl time.Duration)error{
 if err:=valid(actor,token,resource,ttl);err!=nil{return err}
 v.mu.Lock();defer v.mu.Unlock()
 if v.closed{return errors.New("identity vault closed")}
 if existing:=v.sessions[actor];existing!=nil{
  return errors.New("identity already exists; use Rotate")
 }
 if len(v.sessions)>=MaxIdentities{return errors.New("synthetic identity budget exhausted")}
 if v.usedByOther(actor,token){return errors.New("bearer token already belongs to a different synthetic identity")}
 v.sessions[actor]=&record{token:[]byte(token),resource:resource,
  expires:v.nowUTC().Add(ttl),generation:1}
 return nil
}
// Rotate replaces a token for an active identity. Old token bytes are wiped.
// No token or session material is returned to the caller.
func (v *Vault) Rotate(actor,oldToken,newToken string,ttl time.Duration)error{
 v.mu.Lock();defer v.mu.Unlock()
 if v.closed{return errors.New("identity vault closed")}
 r:=v.sessions[actor]
 if r==nil{return errors.New("unknown identity")}
 if !v.nowUTC().Before(r.expires){return errors.New("synthetic session expired")}
 if oldToken==newToken{return errors.New("session token did not change")}
 if err:=valid(actor,newToken,r.resource,ttl);err!=nil{return err}
 if !equal(r.token,[]byte(oldToken)){return errors.New("stale session rotation refused")}
 if v.usedByOther(actor,newToken){return errors.New("rotated token belongs to a different synthetic identity")}
 wipe(r.token)
 r.token=[]byte(newToken)
 r.expires=v.nowUTC().Add(ttl)
 r.generation++
 return nil
}
func equal(a,b []byte)bool{
 if len(a)!=len(b){return false}
 var same byte
 for i:=range a{same|=a[i]^b[i]}
 return same==0
}
// Use runs a trusted transport callback with an ephemeral token copy.
// The callback must never log, persist or return the credential. Its errors
// are replaced with a generic error to avoid accidental secret disclosure.
func (v *Vault) Use(actor string,fn func(token,resource string)error)error{
 if fn==nil{return errors.New("session transport callback required")}
 v.mu.Lock()
 if v.closed{v.mu.Unlock();return errors.New("identity vault closed")}
 r:=v.sessions[actor]
 if r==nil{v.mu.Unlock();return errors.New("unknown identity")}
 if !v.nowUTC().Before(r.expires){v.mu.Unlock();return errors.New("synthetic session expired")}
 token:=string(r.token)
 resource:=r.resource
 v.mu.Unlock()
 if err:=fn(token,resource);err!=nil{return errors.New("trusted synthetic session operation failed")}
 return nil
}
func (v *Vault) Revoke(actor string){
 v.mu.Lock();defer v.mu.Unlock()
 if r:=v.sessions[actor];r!=nil{wipe(r.token);delete(v.sessions,actor)}
}
func (v *Vault) View(actor string)(View,error){
 v.mu.Lock();defer v.mu.Unlock()
 if !actorPattern.MatchString(actor){return View{},errors.New("invalid actor")}
 if v.closed{return View{},errors.New("identity vault closed")}
 r:=v.sessions[actor]
 if r==nil{return View{Actor:actor,HasSession:false},nil}
 live:=v.nowUTC().Before(r.expires)
 out:=View{Actor:actor,HasSession:live,Generation:r.generation}
 if live{out.ExpiresAt=r.expires.UTC().Format(time.RFC3339)}
 return out,nil
}
// Close explicitly destroys all active token buffers. It does not promise
// zeroization of immutable Go strings held temporarily by callbacks.
func (v *Vault) Close(){
 v.mu.Lock();defer v.mu.Unlock()
 for key,r:=range v.sessions{wipe(r.token);delete(v.sessions,key)}
 v.closed=true
}
func (v *Vault) Count()int{
 v.mu.Lock();defer v.mu.Unlock()
 return len(v.sessions)
}
func (v *Vault) String()string{
 return fmt.Sprintf("BunnyMind identity vault (redacted, %d identities)",v.Count())
}
