// Package bunnyplanner turns caller-supplied inventory diffs into bounded,
// deterministic review tasks. It cannot execute scans or validate discoveries.
package bunnyplanner

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "regexp"
 "sort"
 "strings"
)

const MaxSuggestions=64
var safeID=regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var safeRelation=map[string]bool{"contains":true,"calls":true,"depends_on":true,"protected_by":true,"resolves_to":true}
type ChangeSet struct{
 Added []string `json:"added"`
 Removed []string `json:"removed"`
 Changed []string `json:"changed"`
 AddedLinks []string `json:"added_links"`
 RemovedLinks []string `json:"removed_links"`
}
type SuggestedTask struct{
 ID string `json:"id"`
 Title string `json:"title"`
 Kind string `json:"kind"`
 Priority int `json:"priority"`
 DependsOn []string `json:"depends_on,omitempty"`
 MaxAttempts int `json:"max_attempts"`
}
type Plan struct{
 Tasks []SuggestedTask `json:"tasks"`
 TotalChanges int `json:"total_changes"`
 Dropped int `json:"dropped"`
 Limit int `json:"limit"`
 Disclaimer string `json:"disclaimer"`
}
type candidate struct{key string;typeName string;priority int}
func shortHash(s string)string{v:=sha256.Sum256([]byte(s));return hex.EncodeToString(v[:])[:16]}
func checkLink(key string)bool{
 fields:=strings.Split(key,"|")
 return len(fields)==3&&safeID.MatchString(fields[0])&&safeRelation[fields[1]]&&safeID.MatchString(fields[2])
}
// Build creates review-only tasks; it does not update a task board.
// Use the returned tasks explicitly with investigation_board.plan.
func Build(changes ChangeSet,limit int)(Plan,error){
 if limit<=0||limit>MaxSuggestions{return Plan{},fmt.Errorf("limit must be 1..%d",MaxSuggestions)}
 out:=Plan{Tasks:[]SuggestedTask{},Limit:limit,
 Disclaimer:"These are offline review task suggestions derived from caller-provided inventory diffs. No assets or vulnerabilities were independently verified and no network requests were made."}
 selected:=map[string]candidate{}
 insert:=func(items []string,typeName string,priority int,relation bool)error{
  for _,id:=range items{
   if (!relation&&!safeID.MatchString(id))||(relation&&!checkLink(id)){
    return errors.New("invalid asset or relationship identifier in inventory diff")
   }
   key:="asset:"+id
   if relation{key="edge:"+id}
   old,ok:=selected[key]
   if !ok||priority>old.priority{selected[key]=candidate{key:key,typeName:typeName,priority:priority}}
  }
  return nil
 }
 if err:=insert(changes.Changed,"changed asset",5,false);err!=nil{return Plan{},err}
 if err:=insert(changes.Added,"added asset",4,false);err!=nil{return Plan{},err}
 if err:=insert(changes.Removed,"removed asset",3,false);err!=nil{return Plan{},err}
 if err:=insert(changes.AddedLinks,"added relationship",2,true);err!=nil{return Plan{},err}
 if err:=insert(changes.RemovedLinks,"removed relationship",2,true);err!=nil{return Plan{},err}
 ordered:=make([]candidate,0,len(selected))
 for _,v:=range selected{ordered=append(ordered,v)}
 sort.Slice(ordered,func(i,j int)bool{
  if ordered[i].priority!=ordered[j].priority{return ordered[i].priority>ordered[j].priority}
  return ordered[i].key<ordered[j].key
 })
 out.TotalChanges=len(ordered)
 if len(ordered)>limit{out.Dropped=len(ordered)-limit;ordered=ordered[:limit]}
 for _,item:=range ordered{
  h:=shortHash(item.key)
  out.Tasks=append(out.Tasks,SuggestedTask{
   ID:"review_"+h,Title:"Review "+item.typeName+" ref "+h,
   Kind:"review",Priority:item.priority,MaxAttempts:2,DependsOn:[]string{},
  })
 }
 return out,nil
}
