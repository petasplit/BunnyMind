// Package bunnymission defines bounded, explicitly scoped multi-target
// engagement priorities. It schedules metadata only; it never sends traffic.
package bunnymission

import (
 "errors"
 "fmt"
 "net/url"
 "sort"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
)
type Target struct {
 Origin string `json:"origin"`
 Priority int `json:"priority"`
}
type Profile struct{
 EngagementID string `json:"engagement_id"`
 Mode string `json:"mode"`
 TimeBudgetMinutes int `json:"time_budget_minutes"`
 Targets []Target `json:"targets"`
}
type Allocation struct {
 Origin string `json:"origin"`
 Priority int `json:"priority"`
 MaxRequests int `json:"max_requests"`
 MaxMinutes int `json:"max_minutes"`
}
type Schedule struct {
 Mode string `json:"mode"`
 EngagementID string `json:"engagement_id"`
 TimeBudgetMinutes int `json:"time_budget_minutes"`
 Allocations []Allocation `json:"allocations"`
 PhaseFamilies []string `json:"phase_families"`
 Note string `json:"note"`
}
func exactHTTPS(s string)(string,error){
 u,err:=url.Parse(s)
 if err!=nil||u==nil||u.Scheme!="https"||u.User!=nil||
 u.Hostname()==""||u.Opaque!=""||u.RawQuery!=""||u.Fragment!=""||
 (u.Path!=""&&u.Path!="/")||(u.Port()!=""&&u.Port()!="443")||
 strings.HasSuffix(u.Hostname(),".")||strings.Contains(u.Hostname(),"%"){
  return "",errors.New("a target must be an exact HTTPS origin on port 443")
 }
 return "https://"+strings.ToLower(u.Hostname()),nil
}
func Build(p Profile,manifest bunnyguard.Policy)(Schedule,error){
 if p.EngagementID==""||p.EngagementID!=manifest.EngagementID{
  return Schedule{},errors.New("mission engagement does not match BunnyGuard")
 }
 if p.Mode!="normal"&&p.Mode!="full"{return Schedule{},errors.New("unknown assessment mode")}
 if p.TimeBudgetMinutes<5||p.TimeBudgetMinutes>1440{
  return Schedule{},errors.New("mission duration must be 5..1440 minutes")
 }
 if len(p.Targets)==0||len(p.Targets)>20{
  return Schedule{},errors.New("mission requires 1..20 explicitly approved targets")
 }
 permitted:=map[string]bool{}
 for _,raw:=range manifest.AllowedOrigins{
  if o,err:=exactHTTPS(raw);err==nil{permitted[o]=true}
 }
 targets:=append([]Target(nil),p.Targets...)
 seen:=map[string]bool{}
 weight:=0
 for i:=range targets{
  origin,err:=exactHTTPS(targets[i].Origin)
  if err!=nil||!permitted[origin]||seen[origin]||targets[i].Priority<1||targets[i].Priority>5{
   return Schedule{},fmt.Errorf("mission target %d is unapproved or duplicated",i+1)
  }
  targets[i].Origin=origin
  seen[origin]=true
  weight+=targets[i].Priority
 }
 if manifest.MaxNetworkCalls<len(targets){
  return Schedule{},errors.New("engagement request allowance cannot cover all selected origins")
 }
 sort.SliceStable(targets,func(i,j int)bool{
  if targets[i].Priority!=targets[j].Priority{return targets[i].Priority>targets[j].Priority}
  return targets[i].Origin<targets[j].Origin
 })
 total:=manifest.MaxNetworkCalls
 schedule:=Schedule{Mode:p.Mode,EngagementID:p.EngagementID,
  TimeBudgetMinutes:p.TimeBudgetMinutes,Allocations:[]Allocation{},
  Note:"Offline engagement priorities only. The existing guarded tools enforce network permissions. This profile does not start scans or prove findings.",
 }
 if p.Mode=="normal"{
  schedule.PhaseFamilies=[]string{"scope","recon","authentication","access_control","evidence"}
 }else{
  schedule.PhaseFamilies=[]string{"scope","recon","authentication","access_control",
   "api_review","input_validation","business_logic","session_lifecycle",
   "configuration","component_review","evidence","report"}
 }
 usedRequests,usedMinutes:=0,0
 for i,t:=range targets{
  calls:=0;minutes:=0
  if i==len(targets)-1{
   calls=total-usedRequests
   minutes=p.TimeBudgetMinutes-usedMinutes
  }else{
   calls=total*t.Priority/weight
   if calls<1{calls=1}
   minutes=p.TimeBudgetMinutes*t.Priority/weight
   if minutes<1{minutes=1}
  }
  // Reserve at least one unit for each remaining target.
  remaining:=len(targets)-i-1
  if calls>total-usedRequests-remaining{calls=total-usedRequests-remaining}
  if minutes>p.TimeBudgetMinutes-usedMinutes{minutes=p.TimeBudgetMinutes-usedMinutes}
  schedule.Allocations=append(schedule.Allocations,Allocation{
   Origin:t.Origin,Priority:t.Priority,MaxRequests:calls,MaxMinutes:minutes,
  })
  usedRequests+=calls;usedMinutes+=minutes
  weight-=t.Priority
 }
 return schedule,nil
}
