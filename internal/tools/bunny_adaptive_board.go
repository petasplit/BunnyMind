package tools

import (
 "os"
 "regexp"
 "strings"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyharness"
)

var safeAdaptiveTaskID=regexp.MustCompile(`^[a-z0-9_]{1,48}$`)
func adaptiveReviewTasks(checks []bunnybrowserflow.NextCheck)[]bunnyharness.Task{
 tasks:=make([]bunnyharness.Task,0,len(checks))
 seen:=map[string]bool{}
 for _,check:=range checks{
  id:="auth_"+check.Category
  if !safeAdaptiveTaskID.MatchString(id)||seen[id]||check.Priority<1||check.Priority>5{continue}
  seen[id]=true
  kind:="analysis"
  switch check.Category{
  case "cross_identity_authorization","session_lifecycle","auth_boundary_controls":
   kind="verification"
  case "state_change_review","redirect_boundary_review":
   kind="review"
  }
  tasks=append(tasks,bunnyharness.Task{
   ID:id,Title:"Review observed "+strings.ReplaceAll(check.Category,"_"," "),
   Kind:kind,Priority:check.Priority,MaxAttempts:2,
  })
 }
 return tasks
}
// seedAdaptiveBoard initializes a new investigation board only if none exists.
// Existing audits are never overwritten. The board is a review queue; it does
// NOT execute tests or claim a confirmed vulnerability.
func seedAdaptiveBoard(session string,checks []bunnybrowserflow.NextCheck)(bool,error){
 if session==""||len(checks)==0{return false,nil}
 manager:=boardManager()
 if _,err:=manager.Status(session);err==nil{
  return false,nil
 }else if !os.IsNotExist(err){
  return false,err
 }
 tasks:=adaptiveReviewTasks(checks)
 if len(tasks)==0{return false,nil}
 if _,err:=manager.Init(session,tasks,2);err!=nil{return false,err}
 return true,nil
}
