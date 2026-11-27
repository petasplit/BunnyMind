package bunnybrowserflow

import (
 "context"
 "crypto/tls"
 "errors"
 "fmt"
 "io"
 "net"
 "net/netip"
 "regexp"
 "strings"
 "sync"
 "time"

 "github.com/emersion/go-imap"
 "github.com/emersion/go-imap/client"
 "github.com/enowdev/antares/internal/bunnyegress"
)

// MailboxConfig is operator-controlled, not derived from the target site.
// Each test persona gets its own mailbox identity and expected sender.
type MailboxConfig struct {
 Host string `json:"host"`
 Port int `json:"port"`
 Boxes map[string]MailboxActor `json:"boxes"`
}
type MailboxActor struct{
 Address string `json:"address"`
 Sender string `json:"sender"`
}
type InboxMessage struct{
 UID uint32
 From string
 To []string
 Subject string
 Received time.Time
 Body string
}
type InboxTransport interface {
 Recent(context.Context,MailboxConfig,string,string)([]InboxMessage,error)
}
type IMAPTransport struct{}
var mailHostname=regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{1,251}[A-Za-z0-9])$`)
var validMailboxAddress=regexp.MustCompile(`^[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{3,190}$`)
var verificationCodePattern=regexp.MustCompile(`[0-9]{4,8}`)
func validateMailboxConfig(c MailboxConfig)error{
 if c.Port!=993||!mailHostname.MatchString(c.Host)||net.ParseIP(c.Host)!=nil||
   strings.HasSuffix(c.Host,".")||strings.Contains(c.Host,"..")||
   len(c.Boxes)==0||len(c.Boxes)>MaxActors{
  return errors.New("dedicated IMAP requires TLS port 993, a public DNS hostname and 1..4 configured test mailboxes")
 }
 seen:=map[string]bool{}
 for actor,box:=range c.Boxes{
  if !validActor.MatchString(actor)||!validMailboxAddress.MatchString(box.Address)||
   !validMailboxAddress.MatchString(box.Sender)||
   seen[strings.ToLower(box.Address)]{
   return errors.New("invalid or non-isolated mailbox account")
  }
  seen[strings.ToLower(box.Address)]=true
 }
 return nil
}
func publicIMAPDNS(ctx context.Context,hostname string)(string,error){
 ips,err:=net.DefaultResolver.LookupNetIP(ctx,"ip",hostname)
 if err!=nil||len(ips)==0||len(ips)>32{return "",errors.New("dedicated IMAP DNS resolution failed")}
 for _,ip:=range ips{if !bunnyegress.PublicIP(ip){return "",errors.New("IMAP DNS included a private or special-use destination")}}
 return net.JoinHostPort(ips[0].Unmap().String(),"993"),nil
}
func (IMAPTransport) Recent(ctx context.Context,cfg MailboxConfig,actor,password string)([]InboxMessage,error){
 box,ok:=cfg.Boxes[actor]
 if !ok||password==""{return nil,errors.New("trusted test mailbox credentials unavailable")}
 dialCtx,cancel:=context.WithTimeout(ctx,8*time.Second)
 defer cancel()
 address,err:=publicIMAPDNS(dialCtx,cfg.Host)
 if err!=nil{return nil,err}
 socket,err:=(&net.Dialer{Timeout:5*time.Second}).DialContext(dialCtx,"tcp",address)
 if err!=nil{return nil,errors.New("dedicated IMAP transport unavailable")}
 tlsConn:=tls.Client(socket,&tls.Config{ServerName:cfg.Host,MinVersion:tls.VersionTLS12})
 _=tlsConn.SetDeadline(time.Now().Add(15*time.Second))
 if err:=tlsConn.HandshakeContext(dialCtx);err!=nil{tlsConn.Close();return nil,errors.New("IMAP TLS handshake failed")}
 cli,err:=client.New(tlsConn)
 if err!=nil{tlsConn.Close();return nil,errors.New("IMAP greeting rejected")}
 defer cli.Logout()
 if err:=cli.Login(box.Address,password);err!=nil{return nil,errors.New("dedicated test mailbox authentication rejected")}
 mailbox,err:=cli.Select("INBOX",true)
 if err!=nil{return nil,errors.New("test inbox unavailable")}
 if mailbox.Messages==0{return []InboxMessage{},nil}
 var first uint32=1
 if mailbox.Messages>12{first=mailbox.Messages-11}
 set:=new(imap.SeqSet);set.AddRange(first,mailbox.Messages)
 section:=&imap.BodySectionName{BodyPartName:imap.BodyPartName{Specifier:imap.TextSpecifier}}
 messages:=make(chan *imap.Message,12)
	done:=make(chan error,1)
 go func(){done<-cli.Fetch(set,[]imap.FetchItem{imap.FetchEnvelope,imap.FetchUid,section.FetchItem()},messages)}()
 out:=make([]InboxMessage,0,12)
 for msg:=range messages {
  if msg==nil||msg.Envelope==nil{continue}
  e:=msg.Envelope
  item:=InboxMessage{UID:msg.Uid,Subject:e.Subject,Received:e.Date}
  if len(e.From)>0{item.From=e.From[0].Address()}
  for _,to:=range e.To{item.To=append(item.To,to.Address())}
  if body:=msg.GetBody(section);body!=nil{
   b,_:=io.ReadAll(io.LimitReader(body,4097))
   if len(b)<=4096{item.Body=string(b)}
  }
  out=append(out,item)
 }
 if err:=<-done;err!=nil{return nil,errors.New("IMAP message fetch failed")}
 return out,nil
}
func hasRecipient(msg InboxMessage,address string)bool{
 for _,to:=range msg.To{if strings.EqualFold(to,address){return true}}
 return false
}
func verifiedCode(msg InboxMessage,box MailboxActor,since time.Time,usedUID uint32)(string,bool){
 if msg.UID==0||msg.UID<=usedUID||msg.Received.IsZero()||
  msg.Received.Before(since.Add(-15*time.Second))||
  msg.Received.After(time.Now().Add(2*time.Minute))||
  !strings.EqualFold(msg.From,box.Sender)||!hasRecipient(msg,box.Address)||
  len(msg.Body)>4096||len(msg.Subject)>256{return "",false}
 contextText:=strings.ToLower(msg.Subject+" "+msg.Body)
 if !strings.Contains(contextText,"code")&&!strings.Contains(contextText,"verify")&&
  !strings.Contains(contextText,"verification"){return "",false}
 codes:=verificationCodePattern.FindAllString(msg.Body,-1)
 if len(codes)!=1{return "",false}
 return codes[0],true
}
// TrustedMailboxSecrets keeps OTP codes entirely within the privileged
// browser integration. No mailbox body, sender or code reaches model tools.
type TrustedMailboxSecrets struct{
 Config MailboxConfig
 Transport InboxTransport
 Other Secrets
 Mu sync.Mutex
 requested map[string]time.Time
 consumed map[string]uint32
}
func NewTrustedMailboxSecrets(c MailboxConfig,transport InboxTransport,other Secrets)(*TrustedMailboxSecrets,error){
 if err:=validateMailboxConfig(c);err!=nil{return nil,err}
 if transport==nil||other==nil{return nil,errors.New("trusted inbox and account credential provider required")}
 return &TrustedMailboxSecrets{Config:c,Transport:transport,Other:other,
  requested:map[string]time.Time{},consumed:map[string]uint32{}},nil
}
func (s *TrustedMailboxSecrets) MarkCodeRequested(actor string){
 s.Mu.Lock();defer s.Mu.Unlock()
 if _,ok:=s.Config.Boxes[actor];ok{s.requested[actor]=time.Now().UTC()}
}
func (s *TrustedMailboxSecrets) Resolve(ctx context.Context,actor,key string)(string,error){
 if key!="otp"{return s.Other.Resolve(ctx,actor,key)}
 s.Mu.Lock()
 since,ok:=s.requested[actor]
 last:=s.consumed[actor]
 box,exists:=s.Config.Boxes[actor]
 s.Mu.Unlock()
 if !ok||!exists{return "",errors.New("OTP request not recorded for this test identity")}
 password,err:=s.Other.Resolve(ctx,actor,"imap_password")
 if err!=nil{return "",errors.New("dedicated inbox credential missing")}
 defer func(){password=""}()
 until:=time.NewTimer(65*time.Second);defer until.Stop()
 tick:=time.NewTicker(3*time.Second);defer tick.Stop()
 for {
  messages,err:=s.Transport.Recent(ctx,s.Config,actor,password)
  if err!=nil{return "",errors.New("dedicated IMAP inbox unavailable")}
  var selectedUID uint32
  var code string
  for _,message:=range messages {
   candidate,valid:=verifiedCode(message,box,since,last)
   if valid&&message.UID>selectedUID{selectedUID=message.UID;code=candidate}
  }
  if selectedUID>0{
   s.Mu.Lock()
   if s.consumed[actor]>=selectedUID{s.Mu.Unlock();return "",errors.New("verification code already consumed")}
   s.consumed[actor]=selectedUID
   s.Mu.Unlock()
   return code,nil
  }
  select{
  case <-ctx.Done():return "",ctx.Err()
  case <-until.C:return "",errors.New("verification email did not arrive within the approved window")
  case <-tick.C:
  }
 }
}
func (s *TrustedMailboxSecrets) String()string{
 return fmt.Sprintf("Trusted dedicated test mailbox (%d configured personas; message bodies redacted)",len(s.Config.Boxes))
}
