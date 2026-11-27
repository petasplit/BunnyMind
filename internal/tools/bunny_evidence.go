package tools

import (
	"context"
	"encoding/json"

	"github.com/enowdev/antares/internal/bunnyevidence"
)

// evidenceReviewTool assesses supplied HTTP observations. It does not send
// network requests, reproduce findings or treat user-supplied data as proof.
type evidenceReviewTool struct{}

func (evidenceReviewTool) Name() string { return "review_evidence" }
func (evidenceReviewTool) Description() string {
	return "Review an HTTP finding using repeat positive observations and negative controls. " +
		"Offline only: submitted response bodies are checked for a unique marker and discarded; " +
		"the output contains hashes, counts and evidence gaps but no raw traffic. " +
		"Even a consistent result does NOT verify that the observations are authentic or that an exploit was reproduced."
}
func (evidenceReviewTool) RequiresApproval() bool { return false }
func (evidenceReviewTool) Schema() map[string]any {
	return schema(map[string]any{
		"finding_id": prop("string","Finding identifier, e.g. F-001."),
		"marker": prop("string","Unique expected indicator of at least 6 characters, absent from the request."),
		"observations": map[string]any{
			"type":"array",
			"description":"At least two positive and two control samples for a consistent result.",
			"items":map[string]any{
				"type":"object",
				"properties":map[string]any{
					"sample_id":prop("string","Unique identifier for this supplied sample."),
					"kind":propEnum("Positive proof or negative control.","positive","control"),
					"method":prop("string","HTTP request method."),
					"request_url":prop("string","Absolute request URL; kept out of the output."),
					"request_body":prop("string","Optional raw request body, used only to detect reflected markers."),
					"response_status":prop("integer","HTTP status code."),
					"response_body":prop("string","Captured response body; hashed and not returned."),
				},
				"required":[]string{"sample_id","kind","method","request_url","response_status","response_body"},
			},
		},
	},"finding_id","marker","observations")
}
func (evidenceReviewTool) Execute(_ context.Context,in Input) Result {
	var args bunnyevidence.Submission
	if err:=in.Bind(&args);err!=nil{return Errorf("invalid evidence input: %v",err)}
	assessment,err:=bunnyevidence.Review(args)
	if err!=nil{return Errorf("evidence assessment failed: %v",err)}
	encoded,err:=json.MarshalIndent(assessment,"","  ")
	if err!=nil{return Errorf("cannot format assessment: %v",err)}
	return Text(string(encoded))
}
