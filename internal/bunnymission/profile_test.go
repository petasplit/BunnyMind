package bunnymission

import (
 "testing"

 "github.com/enowdev/antares/internal/bunnyguard"
)
func missionManifest()bunnyguard.Policy{
 return bunnyguard.Policy{EngagementID:"engagement-A",
  AllowedOrigins:[]string{"https://a.example","https://b.example","https://c.example"},
  MaxNetworkCalls:120,AllowedMethods:[]string{"GET","HEAD","POST"}}
}
func TestMissionPrioritiesAndBudgetsAreBounded(t *testing.T){
 p:=Profile{EngagementID:"engagement-A",Mode:"full",TimeBudgetMinutes:80,Targets:[]Target{
  {Origin:"https://c.example",Priority:1},
  {Origin:"https://a.example",Priority:5},
  {Origin:"https://b.example",Priority:2},
 }}
 out,err:=Build(p,missionManifest())
 if err!=nil{t.Fatal(err)}
 if len(out.Allocations)!=3||out.Allocations[0].Origin!="https://a.example"||len(out.PhaseFamilies)<10{
  t.Fatalf("wrong mission: %+v",out)
 }
 requests,minutes:=0,0
 for _,a:=range out.Allocations{
  requests+=a.MaxRequests;minutes+=a.MaxMinutes
  if a.MaxRequests<1||a.MaxMinutes<1{t.Fatalf("allocation starved %v",a)}
 }
 if requests!=120||minutes!=80{t.Fatalf("mission oversubscribed: %d requests %d minutes",requests,minutes)}
 if out.Allocations[0].MaxRequests<=out.Allocations[1].MaxRequests{
  t.Fatal("higher priority target did not get more capacity")
 }
}
func TestMissionCannotExpandAuthorizedScope(t *testing.T){
 p:=Profile{EngagementID:"engagement-A",Mode:"normal",TimeBudgetMinutes:20,
  Targets:[]Target{{Origin:"https://a.example",Priority:3}}}
 for _,target:=range []string{"https://a.example.evil.org","http://a.example","https://b.example:8443","https://a.example/private"}{
  bad:=p;bad.Targets=[]Target{{Origin:target,Priority:3}}
  if _,err:=Build(bad,missionManifest());err==nil{t.Fatalf("unapproved target %s",target)}
 }
 bad:=p;bad.TimeBudgetMinutes=0
 if _,err:=Build(bad,missionManifest());err==nil{t.Fatal("unbounded deadline")}
 bad=p;bad.Mode="everything"
 if _,err:=Build(bad,missionManifest());err==nil{t.Fatal("unknown assessment mode accepted")}
 bad=p;bad.EngagementID="another"
 if _,err:=Build(bad,missionManifest());err==nil{t.Fatal("engagement mismatch")}
 bad=p;bad.Targets=[]Target{{Origin:"https://a.example",Priority:3},{Origin:"https://a.example",Priority:5}}
 if _,err:=Build(bad,missionManifest());err==nil{t.Fatal("duplicate target accepted")}
}
