package tools

import (
 "context"
 "encoding/json"
 "strings"
 "testing"
)
func TestAuthWorkflowAgentToolRunsSyntheticFlow(t *testing.T){
 tool:=authWorkflowLabTool{}
 result:=tool.Execute(context.Background(),Input{SessionID:"synthetic-lab",Args:json.RawMessage(`{"deliberate_exposure":false}`)})
 if result.IsError||!strings.Contains(result.Content,"cross_user_denied_in_synthetic_lab"){t.Fatalf("auth flow tool failed: %s",result.Content)}
}
func TestAuthWorkflowToolRefusesExternalTargetArgument(t *testing.T){
 result:=(authWorkflowLabTool{}).Execute(context.Background(),
 Input{Args:json.RawMessage(`{"deliberate_exposure":true,"target_url":"https://example.org"}`)})
 if !result.IsError{t.Fatal("external target argument silently accepted")}
}
func TestResearchToolRefusesUnexpectedPayload(t *testing.T){
 result:=(researchNextStepTool{}).Execute(context.Background(),
 Input{Args:json.RawMessage(`{"action":"mint_benign_canary","payload":"not-permitted"}`)})
 if !result.IsError{t.Fatal("payload argument silently accepted")}
}
func TestResearchToolCreatesOnlyBenignCanary(t *testing.T){
 result:=(researchNextStepTool{}).Execute(context.Background(),Input{Args:json.RawMessage(`{"action":"mint_benign_canary"}`)})
 if result.IsError||!strings.HasPrefix(result.Content,"BUNNY_BENIGN_"){t.Fatalf("canary result %+v",result)}
}
