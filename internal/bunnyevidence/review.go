// Package bunnyevidence reviews submitted HTTP observations without
// executing requests. Results never establish that a live exploit occurred.
package bunnyevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	maxSamples = 32
	maxRequestBytes = 65536
	maxResponseBytes = 131072
)

// Observation is a caller-supplied HTTP request/response pair.
// The body fields are processed in memory and are excluded from output.
type Observation struct {
	SampleID string `json:"sample_id"`
	Kind string `json:"kind"` // positive | control
	Method string `json:"method"`
	RequestURL string `json:"request_url"`
	RequestBody string `json:"request_body,omitempty"`
	ResponseStatus int `json:"response_status"`
	ResponseBody string `json:"response_body"`
}
type Submission struct {
	FindingID string `json:"finding_id"`
	Marker string `json:"marker"`
	Observations []Observation `json:"observations"`
}
type SampleSummary struct {
	SampleID string `json:"sample_id"`
	Kind string `json:"kind"`
	Status int `json:"status"`
	Method string `json:"method"`
	RequestDigest string `json:"request_sha256"`
	ResponseDigest string `json:"response_sha256"`
	MarkerPresent bool `json:"marker_present"`
	MarkerInRequest bool `json:"marker_in_request"`
}
type Result struct {
	FindingID string `json:"finding_id"`
	Origin string `json:"origin"`
	Assessment string `json:"assessment"`
	PositiveSamples int `json:"positive_samples"`
	ControlSamples int `json:"control_samples"`
	MarkerDigest string `json:"marker_sha256"`
	Samples []SampleSummary `json:"samples"`
	Reasons []string `json:"reasons"`
	Disclaimer string `json:"disclaimer"`
}
func sum(s string)string{h:=sha256.Sum256([]byte(s));return hex.EncodeToString(h[:])}
func isMethod(m string)bool{
	switch m{
	case "GET","HEAD","OPTIONS","POST","PUT","PATCH","DELETE":return true
	default:return false
	}
}
func originOf(raw string)(string,error){
	u,err:=url.Parse(raw)
	if err!=nil||u==nil||(u.Scheme!="http"&&u.Scheme!="https")||u.Host==""||
		u.User!=nil||u.Opaque!=""||u.Fragment!=""{
		return "",errors.New("expected an absolute HTTP(S) URL without credentials or fragment")
	}
	return strings.ToLower(u.Scheme+"://"+u.Host),nil
}

// Review evaluates consistency within data provided by the calling agent.
// Passing means the observation set contains a repeated positive-vs-control
// distinction, NOT that the samples are authentic or independently reproduced.
func Review(input Submission)(Result,error){
	out:=Result{
		FindingID:strings.TrimSpace(input.FindingID),
		Assessment:"inconclusive",
		MarkerDigest:sum(input.Marker),
		Disclaimer:"Offline assessment of caller-supplied observations only; no requests were replayed and the authenticity of evidence was not verified.",
		Samples:[]SampleSummary{},
		Reasons:[]string{},
	}
	if out.FindingID==""||len(out.FindingID)>128{return Result{},errors.New("finding_id must be 1..128 characters")}
	if len(input.Marker)<6||len(input.Marker)>128||strings.TrimSpace(input.Marker)==""{
		return Result{},errors.New("marker must contain 6..128 characters")
	}
	if len(input.Observations)==0||len(input.Observations)>maxSamples{
		return Result{},fmt.Errorf("expected 1..%d observations",maxSamples)
	}
	ids:=map[string]bool{}
	var positiveAbsent,controlPresent,reflected bool
	for _,item:=range input.Observations{
		if strings.TrimSpace(item.SampleID)==""||len(item.SampleID)>64||ids[item.SampleID]{
			return Result{},errors.New("sample IDs must be nonempty, unique, and at most 64 characters")
		}
		ids[item.SampleID]=true
		kind:=strings.ToLower(strings.TrimSpace(item.Kind))
		if kind!="positive"&&kind!="control"{return Result{},fmt.Errorf("sample %s: kind must be positive or control",item.SampleID)}
		method:=strings.ToUpper(strings.TrimSpace(item.Method))
		if !isMethod(method){return Result{},fmt.Errorf("sample %s: unsupported HTTP method",item.SampleID)}
		o,err:=originOf(item.RequestURL)
		if err!=nil{return Result{},fmt.Errorf("sample %s: %w",item.SampleID,err)}
		if out.Origin==""{out.Origin=o}else if out.Origin!=o{
			return Result{},errors.New("all samples must use the same exact scheme/host/port origin")
		}
		if item.ResponseStatus<100||item.ResponseStatus>599{
			return Result{},fmt.Errorf("sample %s: invalid HTTP status",item.SampleID)
		}
		if len(item.RequestURL)>8192||len(item.RequestBody)>maxRequestBytes||len(item.ResponseBody)>maxResponseBytes{
			return Result{},fmt.Errorf("sample %s: request/response exceeds size limit",item.SampleID)
		}
		seen:=strings.Contains(item.ResponseBody,input.Marker)
		echo:=strings.Contains(item.RequestURL,input.Marker)||strings.Contains(item.RequestBody,input.Marker)
		// URL-decoded reflection also fails the evidence gate.
		if decoded,err:=url.QueryUnescape(item.RequestURL);err==nil&&strings.Contains(decoded,input.Marker){echo=true}
		if kind=="positive"{
			out.PositiveSamples++
			if !seen{positiveAbsent=true}
			if echo{reflected=true}
		}else{
			out.ControlSamples++
			if seen{controlPresent=true}
		}
		out.Samples=append(out.Samples,SampleSummary{
			SampleID:item.SampleID,Kind:kind,Status:item.ResponseStatus,Method:method,
			RequestDigest:sum(method+"\n"+item.RequestURL+"\n"+item.RequestBody),
			ResponseDigest:sum(item.ResponseBody),MarkerPresent:seen,MarkerInRequest:echo,
		})
	}
	if out.PositiveSamples<2{out.Reasons=append(out.Reasons,"need at least two positive observations")}
	if out.ControlSamples<2{out.Reasons=append(out.Reasons,"need at least two negative-control observations")}
	if positiveAbsent{out.Reasons=append(out.Reasons,"indicator missing from at least one positive response")}
	if controlPresent{out.Reasons=append(out.Reasons,"indicator appears in at least one negative-control response")}
	if reflected{out.Reasons=append(out.Reasons,"indicator was supplied in a positive request and may only have been reflected")}
	if len(out.Reasons)==0{
		out.Assessment="consistent-provided-observations"
		out.Reasons=[]string{"repeated positive responses contain the marker while submitted negative controls do not"}
	}
	sort.Slice(out.Samples,func(i,j int)bool{return out.Samples[i].SampleID<out.Samples[j].SampleID})
	return out,nil
}
