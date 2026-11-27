// Package bunnybench scores controlled-lab evidence and agent claims.
// It never executes tests or independently authenticates supplied logs.
package bunnybench

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

type Case struct {
	ID string `json:"id"`
	Title string `json:"title,omitempty"`
}
type Manifest struct {
	Benchmark string `json:"benchmark"`
	Cases []Case `json:"cases"`
}
type Trial struct {
	RunID string `json:"run_id"`
	Model string `json:"model"`
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	ProofEvents []string `json:"proof_events"`
	PassedControls []string `json:"passed_controls"`
	Reported []string `json:"reported"`
}
type Study struct {
	Manifest Manifest `json:"manifest"`
	Trials []Trial `json:"trials"`
}
type TrialScore struct {
	RunID string `json:"run_id"`
	Model string `json:"model"`
	TotalCases int `json:"total_cases"`
	ReportedCount int `json:"reported_count"`
	SupportedCount int `json:"supported_count"`
	FalseOrUnsupportedCount int `json:"false_or_unsupported_count"`
	MissedCount int `json:"missed_count"`
	ProofCoverage int `json:"proof_coverage"`
	ControlCoverage int `json:"control_coverage"`
	Precision float64 `json:"precision"`
	Recall float64 `json:"recall"`
	ProofCoverageRate float64 `json:"proof_coverage_rate"`
	DurationSeconds float64 `json:"duration_seconds,omitempty"`
	Supported []string `json:"supported"`
	Unsupported []string `json:"unsupported"`
	Missed []string `json:"missed"`
}
type ModelSummary struct {
	Model string `json:"model"`
	Runs int `json:"runs"`
	MeanPrecision float64 `json:"mean_precision"`
	MeanRecall float64 `json:"mean_recall"`
	MeanProofCoverage float64 `json:"mean_proof_coverage"`
}
type Result struct {
	Benchmark string `json:"benchmark"`
	Trials []TrialScore `json:"trials"`
	Models []ModelSummary `json:"models"`
	Disclaimer string `json:"disclaimer"`
}
func set(in []string)map[string]bool{
	out:=map[string]bool{}
	for _,v:=range in{out[strings.TrimSpace(v)]=true}
	return out
}
func sorted(s map[string]bool)[]string{
	out:=[]string{}
	for k,v:=range s{if v{out=append(out,k)}}
	sort.Strings(out);return out
}
func knownList(ids []string,known map[string]bool,context string)error{
	for _,id:=range ids{
		if strings.TrimSpace(id)==""||!known[id]{
			return fmt.Errorf("%s: unknown/blank case %q",context,id)
		}
	}
	return nil
}
// ScoreStudy scores each run against the same fixed ground truth.
// A "supported" claim requires a reported finding PLUS lab-recorded proof
// PLUS an independently recorded passed negative control for that same case.
func ScoreStudy(s Study)(Result,error){
	out:=Result{
		Benchmark:s.Manifest.Benchmark,
		Trials:[]TrialScore{},
		Models:[]ModelSummary{},
		Disclaimer:"Scores rely on caller-supplied lab event logs and manually mapped report claims. No tests were executed, logs are not authenticated, and scores do not predict real-world vulnerability discovery.",
	}
	if strings.TrimSpace(s.Manifest.Benchmark)==""{return Result{},errors.New("benchmark identifier required")}
	if len(s.Manifest.Cases)==0||len(s.Manifest.Cases)>5000{
		return Result{},errors.New("ground truth must contain between 1 and 5000 cases")
	}
	known:=map[string]bool{}
	for _,c:=range s.Manifest.Cases{
		id:=strings.TrimSpace(c.ID)
		if id==""||id!=c.ID||known[id]{return Result{},fmt.Errorf("invalid or duplicate case %q",c.ID)}
		known[id]=true
	}
	if len(s.Trials)==0||len(s.Trials)>1000{return Result{},errors.New("expected 1..1000 trial runs")}
	seenRun:=map[string]bool{}
	byModel:=map[string]*ModelSummary{}
	for _,t:=range s.Trials{
		if strings.TrimSpace(t.RunID)==""||seenRun[t.RunID]||strings.TrimSpace(t.Model)==""||
			t.DurationSeconds<0||t.DurationSeconds>604800{
			return Result{},fmt.Errorf("invalid or repeated run ID/model/duration: %q",t.RunID)
		}
		seenRun[t.RunID]=true
		if err:=knownList(t.ProofEvents,known,"proof events");err!=nil{return Result{},err}
		if err:=knownList(t.PassedControls,known,"passed controls");err!=nil{return Result{},err}
		proofs,controls,reports:=set(t.ProofEvents),set(t.PassedControls),set(t.Reported)
		supported:=map[string]bool{}
		unsupported:=map[string]bool{}
		missed:=map[string]bool{}
		for id:=range reports{
			if known[id]&&proofs[id]&&controls[id]{supported[id]=true
			}else{unsupported[id]=true}
		}
		for id:=range known{if !supported[id]{missed[id]=true}}
		var proofCoverage,controlCoverage int
		for id:=range known{
			if proofs[id]{proofCoverage++}
			if controls[id]{controlCoverage++}
		}
		sc:=TrialScore{
			RunID:t.RunID,Model:t.Model,TotalCases:len(known),
			ReportedCount:len(reports),SupportedCount:len(supported),
			FalseOrUnsupportedCount:len(unsupported),MissedCount:len(missed),
			ProofCoverage:proofCoverage,ControlCoverage:controlCoverage,
			Recall:float64(len(supported))/float64(len(known)),
			ProofCoverageRate:float64(proofCoverage)/float64(len(known)),
			DurationSeconds:t.DurationSeconds,
			Supported:sorted(supported),Unsupported:sorted(unsupported),Missed:sorted(missed),
		}
		if len(reports)>0{sc.Precision=float64(len(supported))/float64(len(reports))}
		out.Trials=append(out.Trials,sc)
		g:=byModel[t.Model]
		if g==nil{g=&ModelSummary{Model:t.Model};byModel[t.Model]=g}
		g.Runs++
		g.MeanPrecision+=sc.Precision
		g.MeanRecall+=sc.Recall
		g.MeanProofCoverage+=sc.ProofCoverageRate
	}
	for _,g:=range byModel{
		g.MeanPrecision/=float64(g.Runs)
		g.MeanRecall/=float64(g.Runs)
		g.MeanProofCoverage/=float64(g.Runs)
		out.Models=append(out.Models,*g)
	}
	sort.Slice(out.Trials,func(i,j int)bool{return out.Trials[i].RunID<out.Trials[j].RunID})
	sort.Slice(out.Models,func(i,j int)bool{return out.Models[i].Model<out.Models[j].Model})
	return out,nil
}
