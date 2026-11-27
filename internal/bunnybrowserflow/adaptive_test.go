package bunnybrowserflow

import (
 "context"
 "encoding/json"
 "errors"
 "strings"
 "testing"

)

type adaptiveBrowser struct {
 url string
 snaps []AuthSnapshot
 index int
 clicks int
 fills map[string]string
 closeCount *int
}
func (b *adaptiveBrowser) Navigate(_ context.Context,raw string)error{b.url=raw;return nil}
func (b *adaptiveBrowser) Fill(_ context.Context,selector,value string)error{
 if b.fills==nil{b.fills=map[string]string{}}
 b.fills[selector]=value
 return nil
}
func (b *adaptiveBrowser) Click(_ context.Context,selector string)error{b.clicks++;b.index++;return nil}
func (b *adaptiveBrowser) Contains(context.Context,string)(bool,error){return false,nil}
func (b *adaptiveBrowser) CurrentURL(context.Context)(string,error){return b.url,nil}
func (b *adaptiveBrowser) Close(){*b.closeCount++}
func (b *adaptiveBrowser) InspectAuth(context.Context)(AuthSnapshot,error){
 if b.index>=len(b.snaps){return AuthSnapshot{},errors.New("unexpected adaptive state")}
 return b.snaps[b.index],nil
}
type adaptiveFactory struct{b *adaptiveBrowser}
func (f adaptiveFactory)New(_ context.Context,_,origin string)(Browser,error){return f.b,nil}
type adaptiveSecrets struct{started bool;usedOTP bool}
func (s *adaptiveSecrets)MarkCodeRequested(actor string){s.started=true}
func (s *adaptiveSecrets)Resolve(_ context.Context,actor,key string)(string,error){
 switch key{
 case "email":return "owner@example.test",nil
 case "password":return "long-example-password",nil
 case "otp":
  if !s.started{return "",errors.New("email never requested")}
  s.usedOTP=true
  return "654321",nil
 default:return "",errors.New("unknown credential key")
 }
}
func TestAdaptiveFormDetectionAndOTP(t *testing.T){
 count:=0
 b:=&adaptiveBrowser{closeCount:&count,snaps:[]AuthSnapshot{
  {Fields:[]AuthField{{Selector:"#email",Kind:"email"},{Selector:"#password",Kind:"password"},
   {Selector:"#password2",Kind:"confirm_password"}},Actions:[]AuthAction{{Selector:"#register",Kind:"signup"}}},
  {Fields:[]AuthField{{Selector:"#code",Kind:"otp"}},Actions:[]AuthAction{{Selector:"#verify",Kind:"verify"}}},
  {SignedIn:true},
 }}
 scope:=sampleScope()
 secrets:=&adaptiveSecrets{}
 result,err:=RunAdaptiveApproved(context.Background(),AdaptiveConfig{
  Actor:"owner",Mode:"signup",EntryPath:"/",
 },scope,adaptiveFactory{b},secrets,nil,approvedManifest())
 if err!=nil{t.Fatal(err)}
 if result.Outcome!="sign_in_indicator_observed"||!result.UsedMailboxOTP||
  b.clicks!=2||count!=1||!secrets.usedOTP{
  t.Fatalf("adaptive form did not complete: %+v clicks=%d closed=%d",result,b.clicks,count)
 }
 if b.fills["#password2"]!="long-example-password"{t.Fatal("confirmation password not populated")}
 data,_:=json.Marshal(result)
 for _,secret:=range []string{"654321","owner@example.test","long-example-password","password2"}{
  if strings.Contains(string(data),secret){t.Fatalf("secret/selector leaked: %s",secret)}
 }
}
func TestUnknownFormRequiresReviewNoSubmitting(t *testing.T){
 closed:=0
 b:=&adaptiveBrowser{closeCount:&closed,snaps:[]AuthSnapshot{{Fields:[]AuthField{{Selector:"#email",Kind:"email"}}}}}
 result,err:=RunAdaptiveApproved(context.Background(),AdaptiveConfig{Actor:"owner",Mode:"login",EntryPath:"/"},
  sampleScope(),adaptiveFactory{b},&adaptiveSecrets{},nil,approvedManifest())
 if err!=nil{t.Fatal(err)}
 if result.Outcome!="unknown_or_unsupported_auth_form"||b.clicks!=0{t.Fatalf("unexpected submission: %+v",result)}
}
func TestAdaptiveRejectsScopeAndUnsafeConfig(t *testing.T){
 cases:=[]AdaptiveConfig{
  {Actor:"owner",Mode:"admin",EntryPath:"/"},
  {Actor:"owner",Mode:"login",EntryPath:"//evil"},
  {Actor:"owner",Mode:"login",EntryPath:"/../private"},
  {Actor:"owner/evil",Mode:"login",EntryPath:"/"},
 }
 for _,c:=range cases{if err:=validateAdaptive(c);err==nil{t.Fatalf("allowed unsafe adaptive config %+v",c)}}
 scope:=sampleScope();scope.ApprovedPostPaths=nil
 if _,err:=RunAdaptiveApproved(context.Background(),AdaptiveConfig{Actor:"owner",Mode:"login",EntryPath:"/"},
  scope,adaptiveFactory{},&adaptiveSecrets{},nil,approvedManifest());err==nil{
  t.Fatal("auth flow was allowed without authorized POST destinations")
 }
 wrong:=approvedManifest();wrong.EngagementID="other"
 if _,err:=ValidateApprovedScope(sampleScope(),wrong);err==nil{t.Fatal("scope mismatch accepted")}
}
func TestSnapshotOnlyAcceptsStructuralSelectors(t *testing.T){
 good:=AuthSnapshot{
  Fields:[]AuthField{{Selector:"#email",Kind:"email"},
   {Selector:"body>form:nth-of-type(1)>input:nth-of-type(2)",Kind:"password"}},
  Actions:[]AuthAction{{Selector:"#login",Kind:"login"}},
  Links:[]AuthLink{{Path:"/register",Kind:"signup"}},
 }
 if err:=validateAuthSnapshot(good);err!=nil{t.Fatalf("generated selectors invalid: %v",err)}
 variants:=[]string{
  "input[value=secret]",
  "body>input:nth-of-type(1);alert(1)",
  "body>script",
  "form:nth-of-type(1) input",
 }
 for _,selector:=range variants{
  snap:=good
  snap.Fields=[]AuthField{{Selector:selector,Kind:"email"}}
  if err:=validateAuthSnapshot(snap);err==nil{t.Fatalf("unsafe selector accepted %q",selector)}
 }
}
