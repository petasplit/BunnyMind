package tools

import (
 "testing"

 "github.com/enowdev/antares/internal/bunnybrowserflow"
 "github.com/enowdev/antares/internal/bunnyharness"
)
func TestAdaptiveReviewTasksRemainBoundedAndNonExecuting(t *testing.T){
 tasks:=adaptiveReviewTasks([]bunnybrowserflow.NextCheck{
  {Category:"cross_identity_authorization",Priority:5},
  {Category:"session_lifecycle",Priority:4},
  {Category:"state_change_review",Priority:3},
  {Category:"transport_recovery",Priority:2},
  {Category:"transport_recovery",Priority:2},
  {Category:"unsafe/path",Priority:5},
 })
 if len(tasks)!=4{t.Fatalf("invalid or duplicate queue entries persisted: %+v",tasks)}
 if err:=bunnyharness.ValidatePlan(tasks,2);err!=nil{t.Fatalf("board rejected adaptive review plan: %v",err)}
 if tasks[0].Kind!="verification"||tasks[2].Kind!="review"||tasks[3].Kind!="analysis"{
  t.Fatalf("unexpected review task classes %+v",tasks)
 }
}
