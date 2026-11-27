package bunnybrowserflow

import (
 "context"
 "crypto/tls"
 "errors"
 "io"
 "fmt"
 "net"
 "net/netip"
 "regexp"
 "strings"
 "sync"
 "time"

 "github.com/emersion/go-imap"
 "github.com/emersion/go-imap/client"
)

var mailboxHostname=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{1,251}[a-zA-Z0-9]$`)
var mailAddress=regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
var verificationCodeRE=regexp.MustCompile(`\b[0-9]{6,8}\b`)

type MailboxSettings struct{
 Host string `json:"host"`
 Sender string `json:"sender"`
}
type mailboxCheckpoint struct{
 uid uint32
 armedAt time.Time
 recipient string
}
type IMAPOTP struct{
 Settings map[string]MailboxSettings
 Credentials Secrets
 mu sync.Mutex
 checkpoints map[string]mailboxCheckpoint
}
// NewIMAPOTP binds mailbox access to operator-declared server and expected
// sender. Account addresses and IMAP app passwords are retrieved from the
// per-actor OS keyring via the existing trusted Secrets port.
func NewIMAPOTP(settings map[string]MailboxSettings,credentials Secrets)(*IMAPOTP,error){
 if len(settings)==0||len(settings)>MaxActors||credentials==nil{
  return nil,errors.New("1..4 explicitly configured mailbox identities required")
 }
 for actor,c:=range settings{
  if !validActor.MatchString(actor)||!mailboxHostname.MatchString(c.Host)||
   strings.Contains(c.Host,"..")||!mailAddress.MatchString(c.Sender)||
   net.ParseIP(c.Host)!=nil{
   return nil,errors.New("invalid explicitly approved IMAP mailbox host or sender")
  }
 }
 return &IMAPOTP{Settings:settings,Credentials:credentials,checkpoints:map[string]mailboxCheckpoint{}},nil
}
func verifyMailIP(ip netip.Addr)bool{
 if !ip.IsValid(){return false}
 ip=ip.Unmap()
 if !ip.IsGlobalUnicast()||ip.IsPrivate()||ip.IsLoopback()||
   ip.IsLinkLocalUnicast()||ip.IsMulticast()||ip.IsUnspecified(){return false}
 for _,cidr:=range []string{"100.64.0.0/10","192.0.0.0/24","192.0.2.0/24",
  "198.18.0.0/15","198.51.100.0/24","203.0.113.0/24",
  "2001:db8::/32","2001::/32","2002::/16"}{
  if netip.MustParsePrefix(cidr).Contains(ip){return false}
 }
 return true
}
func (m *IMAPOTP) login(ctx context.Context,actor string)(*client.Client,error){
 cfg,ok:=m.Settings[actor]
 if !ok{return nil,errors.New("mailbox is not approved for this persona")}
 user,err:=m.Credentials.Resolve(ctx,actor,"imap_user")
 if err!=nil{return nil,errors.New("trusted mailbox user is missing")}
 pass,err:=m.Credentials.Resolve(ctx,actor,"imap_password")
 if err!=nil{return nil,errors.New("trusted mailbox password is missing")}
 lookupCtx,cancel:=context.WithTimeout(ctx,5*time.Second)
 defer cancel()
 ips,err:=net.DefaultResolver.LookupNetIP(lookupCtx,"ip",cfg.Host)
 if err!=nil||len(ips)==0{return nil,errors.New("approved IMAP server resolution failed")}
 for _,ip:=range ips{
  if !verifyMailIP(ip){return nil,errors.New("mailbox host resolved to a restricted IP")}
 }
 nd:=&net.Dialer{Timeout:5*time.Second}
 conn,err:=nd.DialContext(ctx,"tcp",net.JoinHostPort(ips[0].Unmap().String(),"993"))
 if err!=nil{return nil,errors.New("cannot connect to approved IMAP host")}
 tlsConn:=tls.Client(conn,&tls.Config{ServerName:cfg.Host,MinVersion:tls.VersionTLS12})
 if err:=tlsConn.HandshakeContext(ctx);err!=nil{tlsConn.Close();return nil,errors.New("IMAP TLS validation failed")}
 cli,err:=client.New(tlsConn)
 if err!=nil{tlsConn.Close();return nil,errors.New("IMAP protocol handshake failed")}
 if err:=cli.Login(user,pass);err!=nil{cli.Logout();return nil,errors.New("IMAP authentication failed")}
 return cli,nil
}
func (m *IMAPOTP) Arm(ctx context.Context,actor string)error{
 cli,err:=m.login(ctx,actor)
 if err!=nil{return err}
 defer cli.Logout()
 mailbox,err:=cli.Select("INBOX",true)
 if err!=nil{return errors.New("trusted mailbox INBOX not available")}
 recipient,err:=m.Credentials.Resolve(ctx,actor,"email")
 if err!=nil||!mailAddress.MatchString(recipient){return errors.New("test-account recipient unavailable")}
 if mailbox.UidNext==0{return errors.New("IMAP UID checkpoint unavailable")}
 m.mu.Lock()
 m.checkpoints[actor]=mailboxCheckpoint{uid:mailbox.UidNext,armedAt:time.Now().UTC(),recipient:recipient}
 m.mu.Unlock()
 return nil
}
func extractVerifiedCode(body,sender,recipient string,message *imap.Message,since time.Time)(string,bool){
 if message==nil||message.Envelope==nil||message.Envelope.Date.Before(since.Add(-10*time.Second)){return "",false}
 env:=message.Envelope
 trustedSender:=false
 for _,from:=range env.From{
  if from!=nil&&strings.EqualFold(from.Address(),sender){trustedSender=true}
 }
 recipientMatch:=false
 for _,to:=range env.To{
  if to!=nil&&strings.EqualFold(to.Address(),recipient){recipientMatch=true}
 }
 if !trustedSender||!recipientMatch{return "",false}
 found:=verificationCodeRE.FindAllString(body,2)
 if len(found)!=1{return "",false}
 return found[0],true
}
func (m *IMAPOTP) check(ctx context.Context,actor string,checkpoint mailboxCheckpoint)(string,error){
 cli,err:=m.login(ctx,actor)
 if err!=nil{return "",err}
 defer cli.Logout()
 box,err:=cli.Select("INBOX",true)
 if err!=nil{return "",errors.New("mailbox read denied")}
 if box.Messages==0||box.UidNext<=checkpoint.uid{return "",nil}
 // Scan no more than 20 recent messages; do not enumerate older mail.
 start:=uint32(1)
 if box.Messages>20{start=box.Messages-19}
 seq:=new(imap.SeqSet);seq.AddRange(start,box.Messages)
	section:=&imap.BodySectionName{}
 items:=[]imap.FetchItem{imap.FetchEnvelope,imap.FetchUid,section.FetchItem()}
 messages:=make(chan *imap.Message,20)
	done:=make(chan error,1)
	go func(){done<-cli.Fetch(seq,items,messages)}()
 var candidates []string
 for msg:=range messages{
  if msg==nil||msg.Uid<checkpoint.uid{continue}
  if ctx.Err()!=nil{continue}
  body:=msg.GetBody(section)
  if body==nil{continue}
  b,_:=io.ReadAll(io.LimitReader(body,maxMailBytes+1))
  if len(b)>maxMailBytes{continue}
  text,err:=readMailText(b)
  if err!=nil{continue}
  code,ok:=extractVerifiedCode(text,m.Settings[actor].Sender,checkpoint.recipient,msg,checkpoint.armedAt)
  if ok{candidates=append(candidates,code)}
 }
 if err:=<-done;err!=nil{return "",errors.New("IMAP message fetch failed")}
 if len(candidates)>1{return "",errors.New("multiple matching codes require operator review")}
 if len(candidates)==1{return candidates[0],nil}
 return "",nil
}
func (m *IMAPOTP) Wait(ctx context.Context,actor string)(string,error){
 m.mu.Lock();checkpoint,armed:=m.checkpoints[actor];m.mu.Unlock()
 if !armed{return "",errors.New("mailbox was not armed before authentication")}
 timeout,cancel:=context.WithTimeout(ctx,75*time.Second)
 defer cancel()
 for attempts:=0;attempts<12;attempts++{
  code,err:=m.check(timeout,actor,checkpoint)
  if err!=nil{return "",err}
  if code!=""{
   m.mu.Lock();delete(m.checkpoints,actor);m.mu.Unlock()
   return code,nil
  }
  select{
  case <-timeout.Done():return "",errors.New("trusted verification email not received")
  case <-time.After(5*time.Second):
  }
 }
 return "",fmt.Errorf("verification window exhausted for %s",actor)
}
