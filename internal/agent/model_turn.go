package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/enowdev/antares/internal/llm"
)

// validateToolCallArguments catches provider streams that finish with a
// truncated JSON argument payload. Without this check the malformed call reaches
// the tool, fails Bind with unexpected EOF, and consumes the turn instead of
// using the existing provider-glitch retry path.
func validateToolCallArguments(resp *llm.Response) error {
	if resp == nil {
		return nil
	}
	for i := range resp.ToolCalls {
		call := &resp.ToolCalls[i]
		if strings.TrimSpace(call.Arguments) == "" {
			call.Arguments = "{}"
			continue
		}
		var args map[string]any
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return fmt.Errorf("malformed tool_call arguments for %s: %w", call.Name, err)
		}
	}
	return nil
}

// recoverReadOnlyToolCall recognizes a small local model's exact JSON
// pseudo-tool-call output when a provider didn't encode a native tool_calls
// object. Only preapproved read-only tools can be recovered, and their ordinary
// tool implementations still enforce toolset, guard and network policy.
// Arbitrary code/shell/authenticated requests are NEVER recovered this way.
func recoverReadOnlyToolCall(resp *llm.Response, available func(string) bool) bool {
 if resp==nil||len(resp.ToolCalls)>0{return false}
 raw:=strings.TrimSpace(resp.Content)
 if len(raw)<10||len(raw)>4096||!strings.HasPrefix(raw,"{"){return false}
 var envelope struct {
  Name string `json:"name"`
  Arguments json.RawMessage `json:"arguments"`
 }
 dec:=json.NewDecoder(strings.NewReader(raw))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(&envelope);err!=nil{return false}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return false}
 switch envelope.Name {
 case "web_fetch","web_search","scoped_read","read_file","list_files","glob","grep":
 default:return false
 }
 if !available(envelope.Name){return false}
 // An object, not a JSON string, array or executable payload.
 var args map[string]any
 if err:=json.Unmarshal(envelope.Arguments,&args);err!=nil||args==nil{return false}
 if envelope.Name=="scoped_read" {
  if m,ok:=args["method"].(string);ok&&m!="GET"&&m!="HEAD"{return false}
 }
 resp.Content=""
 resp.ToolCalls=[]llm.ToolCall{{
  ID:newID("tool"),
  Name:envelope.Name,
  Arguments:string(envelope.Arguments),
 }}
 return true
}

// callModel runs one completion, streaming when enabled.
func (a *Agent) callModel(ctx context.Context, client llm.Client, req llm.Request, stream bool, emit Emit) (*llm.Response, error) {
	if !stream {
		resp, err := client.Chat(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Reasoning != "" {
			_ = emit(Event{Type: EventReasoning, Delta: resp.Reasoning})
		}
		if resp.Content != "" {
			_ = emit(Event{Type: EventText, Delta: resp.Content})
		}
		return resp, nil
	}

	return client.Stream(ctx, req, func(ev llm.Event) error {
		switch ev.Type {
		case llm.EventText:
			return emit(Event{Type: EventText, Delta: ev.Delta})
		case llm.EventReasoning:
			if a.config().Display.ShowReasoning {
				return emit(Event{Type: EventReasoning, Delta: ev.Delta})
			}
		}
		return nil
	})
}
