package bunnybrowserflow

import (
 "encoding/json"
 "strings"
 "testing"

 "github.com/enowdev/antares/internal/browser"
)

func TestRedactedTrafficContainsNoCredentialsOrRawEndpoints(t *testing.T){
 records:=[]browser.NetworkRequest{
  {
   URL:"https://staging.example/accounts/123?token=my-secret-query",
   Method:"GET",
   Headers:map[string]string{"Authorization":"Bearer my-private-token","Cookie":"session=my-session-cookie"},
   PostData:"password=my-secret",
   Response:&browser.NetworkResponse{
    URL:"https://staging.example/accounts/123?secret=another",
    Status:200,Headers:map[string]string{"Set-Cookie":"super-secret"},
   },
  },
  {URL:"https://staging.example/login?otp=123456",Method:"POST",Failed:"net::ERR_BLOCKED_BY_CLIENT"},
  {URL:"https://offscope.example/secret",Method:"GET",Response:&browser.NetworkResponse{Status:200}},
 }
 out:=redactTraffic("owner",3,records,map[string]bool{"https://staging.example":true})
 if len(out)!=2||out[0].Status!=200||out[1].Outcome!="failed"{
  t.Fatalf("unexpected summary %+v",out)
 }
 b,err:=json.Marshal(out);if err!=nil{t.Fatal(err)}
 for _,secret:=range []string{"my-secret-query","my-private-token","my-session-cookie","my-secret","123456","/accounts/123","/login","offscope.example","Set-Cookie"}{
  if strings.Contains(string(b),secret){t.Fatalf("leaked unredacted data: %s",secret)}
 }
 if len(out[0].PathSHA256)!=64||len(out[0].ReceiptSHA256)!=64{t.Fatalf("invalid evidence hashes: %+v",out[0])}
}
func TestTrafficHashIgnoresQueryButBindsStatus(t *testing.T){
 same:=func(query string,status int)browser.NetworkRequest{
  return browser.NetworkRequest{
   URL:"https://staging.example/resource?id="+query,
   Method:"GET",Response:&browser.NetworkResponse{Status:status},
  }
 }
 allowed:=map[string]bool{"https://staging.example":true}
 first:=redactTraffic("owner",1,[]browser.NetworkRequest{same("first-secret",200)},allowed)[0]
 otherQuery:=redactTraffic("owner",1,[]browser.NetworkRequest{same("second-secret",200)},allowed)[0]
 otherStatus:=redactTraffic("owner",1,[]browser.NetworkRequest{same("first-secret",403)},allowed)[0]
 if first.PathSHA256!=otherQuery.PathSHA256{t.Fatal("query influenced endpoint identity")}
 if first.ReceiptSHA256!=otherQuery.ReceiptSHA256{t.Fatal("query influenced receipt")}
 if first.ReceiptSHA256==otherStatus.ReceiptSHA256{t.Fatal("HTTP status not bound to receipt")}
}
func TestTrafficBoundedToMaxReceipts(t *testing.T){
 request:=browser.NetworkRequest{URL:"https://staging.example/a",Method:"GET",Response:&browser.NetworkResponse{Status:200}}
 requests:=make([]browser.NetworkRequest,MaxTrafficReceipts+50)
 for i:=range requests{requests[i]=request}
 got:=redactTraffic("owner",1,requests,map[string]bool{"https://staging.example":true})
 if len(got)!=MaxTrafficReceipts{t.Fatalf("not bounded: %d",len(got))}
 if len(redactTraffic("bad/name",1,requests,map[string]bool{"https://staging.example":true}))!=0{
  t.Fatal("unsafe actor accepted")
 }
}
