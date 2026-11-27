// Package bunnysarif exports recorded finding metadata to SARIF 2.1.0.
// No exploit body, access token, raw URL query or private request data enters
// the output; a manually triaged finding is not independently verified.
package bunnysarif

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "net/url"
 "strings"

 "github.com/enowdev/antares/internal/findings"
)
type Result struct{
 RuleID string `json:"ruleId"`
 Level string `json:"level"`
 Message map[string]string `json:"message"`
 PartialFingerprints map[string]string `json:"partialFingerprints"`
 Properties map[string]any `json:"properties"`
 Locations []map[string]any `json:"locations,omitempty"`
}
type Rule struct{
 ID string `json:"id"`
 Name string `json:"name"`
 ShortDescription map[string]string `json:"shortDescription"`
}
type Driver struct{
 Name string `json:"name"`
 InformationURI string `json:"informationUri"`
 Rules []Rule `json:"rules"`
}
type Run struct{
 Tool map[string]Driver `json:"tool"`
 Results []Result `json:"results"`
}
type Document struct{
 Version string `json:"version"`
 Schema string `json:"$schema"`
 Runs []Run `json:"runs"`
}
func level(sev findings.Severity)string{
 switch sev{case findings.Critical,findings.High:return "error"
 case findings.Medium:return "warning"
 default:return "note"}
}
func safeTitle(s string)string{
 s=strings.TrimSpace(s)
 if len(s)>180{s=s[:180]}
 // User-provided freeform titles may contain query tokens; redact generic
 // secret-looking fragments instead of exporting a raw report body.
 for _,part:=range strings.Fields(s){
  lower:=strings.ToLower(part)
  if strings.Contains(lower,"token=")||strings.Contains(lower,"password=")||
   strings.Contains(lower,"bearer")||strings.Contains(lower,"secret="){
   s=strings.ReplaceAll(s,part,"[REDACTED]")
  }
 }
 return s
}
func safeOrigin(raw string)string{
 u,err:=url.Parse(raw)
 if err!=nil||u==nil||u.User!=nil||
  (u.Scheme!="https"&&u.Scheme!="http")||u.Hostname()==""{return ""}
 return strings.ToLower(u.Scheme+"://"+u.Host)
}
func Build(records []findings.Finding)([]byte,error){
 rules:=map[string]Rule{}
 results:=[]Result{}
 for _,f:=range records{
  if f.Status==findings.StatusDuplicate||f.Status==findings.StatusWontfix{continue}
  category:=strings.TrimSpace(f.CWE)
  if category==""||len(category)>32||!strings.HasPrefix(category,"CWE-"){
   category="BunnyMind-Finding"
  }
  if _,ok:=rules[category];!ok{
   rules[category]=Rule{ID:category,Name:category,ShortDescription:map[string]string{
    "text":"Recorded potential security issue — independently verify evidence."}}
  }
  title:=safeTitle(f.Title)
  if title==""{title="Recorded security finding"}
  key:=sha256.Sum256([]byte(f.ID+"|"+f.Target+"|"+f.Title+"|"+f.CWE))
  outcome:=Result{
   RuleID:category,Level:level(f.Severity),
   Message:map[string]string{"text":title},
   PartialFingerprints:map[string]string{"bunnymindFindingHash":hex.EncodeToString(key[:])},
   Properties:map[string]any{"finding_id":f.ID,
    "recorded_severity":string(f.Severity),"triage_status":string(f.Status),
    "evidence_status":"unattested; requires independent verification"},
  }
  if origin:=safeOrigin(f.Target);origin!=""{
   outcome.Locations=[]map[string]any{{
    "physicalLocation":map[string]any{
     "artifactLocation":map[string]string{"uri":origin},
    },
   }}
  }
  results=append(results,outcome)
 }
 ordered:=[]Rule{}
 for _,r:=range rules{ordered=append(ordered,r)}
 // Rules are sorted for reproducible CI diffs.
 sort.Slice(ordered,func(i,j int)bool{return ordered[i].ID<ordered[j].ID})
 doc:=Document{
  Version:"2.1.0",
  Schema:"https://json.schemastore.org/sarif-2.1.0.json",
  Runs:[]Run{{
   Tool:map[string]Driver{"driver":{Name:"BunnyMind",
    InformationURI:"https://github.com/petasplit/BunnyMind",Rules:ordered}},
   Results:results,
  }},
 }
 return json.MarshalIndent(doc,"","  ")
}
