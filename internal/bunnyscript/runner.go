package bunnyscript

import (
 "bytes"
 "context"
 "embed"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "strconv"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnyartifact"
 "github.com/enowdev/antares/internal/bunnyegress"
 "github.com/enowdev/antares/internal/bunnyguard"
)

//go:embed runner.py
var pythonTemplates embed.FS

type Secrets interface{
 Resolve(context.Context,string,string)(string,error)
}
type Runner struct{
 Python string
 Root string
 EncryptionKey []byte
 Secrets Secrets
}
type observation struct {
 SampleID string `json:"sample_id"`
 Kind string `json:"kind"`
 Persona string `json:"persona"`
 Status int `json:"status"`
 RequestSHA256 string `json:"request_sha256"`
 ResponseSHA256 string `json:"response_sha256"`
 MarkerPresent bool `json:"marker_present"`
 Truncated bool `json:"truncated"`
 ObservedAt string `json:"observed_at"`
 RequestB64 string `json:"request_b64"`
 ResponseB64 string `json:"response_b64"`
}
type trace struct{
 Version int `json:"version"`
 EngagementID string `json:"engagement_id"`
 RunID string `json:"run_id"`
 Observations []observation `json:"observations"`
}
func Generate(plan Plan)([]byte,error){
 template,err:=pythonTemplates.ReadFile("runner.py")
 if err!=nil{return nil,err}
 b,err:=json.Marshal(plan)
 if err!=nil{return nil,err}
 source:=strings.ReplaceAll(string(template),"__BUNNY_PLAN_LITERAL__",strconv.Quote(string(b)))
 if strings.Contains(source,"__BUNNY_PLAN_LITERAL__"){return nil,errors.New("script generator failed")}
 return []byte(source),nil
}
func validateTrace(raw []byte,p Plan)(EvidenceSummary,error){
 if len(raw)==0||len(raw)>4*1024*1024{return EvidenceSummary{},errors.New("missing or oversized raw transcript")}
 var t trace
 if json.Unmarshal(raw,&t)!=nil||t.Version!=1||t.EngagementID!=p.EngagementID||
 t.RunID!=p.RunID||len(t.Observations)!=len(p.Cases){
  return EvidenceSummary{},errors.New("captured transcript does not match approved scenario")
 }
 summary:=EvidenceSummary{EngagementID:p.EngagementID,RunID:p.RunID,Cases:len(p.Cases),
  RawEvidenceSHA256:SHA(raw),
  Limitations:"Consistent marker/status evidence is not independent proof of a vulnerability. Full request/response captures are encrypted locally; each HTTP response body is bounded to 64 KiB and may be flagged truncated.",
  Receipts:[]SampleReceipt{},
 }
 for i,o:=range t.Observations{
  expected:=p.Cases[i]
  if o.SampleID!=expected.SampleID||o.Kind!=expected.Kind||o.Persona!=expected.Persona{
   return EvidenceSummary{},fmt.Errorf("transcript sample %d does not match approved plan",i+1)
  }
  rq,e:=base64.StdEncoding.Strict().DecodeString(o.RequestB64)
  if e!=nil||len(rq)<10||len(rq)>8192||SHA(rq)!=o.RequestSHA256{
   return EvidenceSummary{},errors.New("request capture hash mismatch")
  }
  rs,e:=base64.StdEncoding.Strict().DecodeString(o.ResponseB64)
  if e!=nil||len(rs)<15||len(rs)>70000||SHA(rs)!=o.ResponseSHA256{
   return EvidenceSummary{},errors.New("response capture hash mismatch")
  }
  if !bytes.HasPrefix(rq,[]byte(expected.Method+" "+expected.Path+" HTTP/1.1\r\n")){
   return EvidenceSummary{},errors.New("request capture destination differs from approved plan")
  }
  cut:=bytes.Index(rs,[]byte("\r\n\r\n"))
  if cut<0{return EvidenceSummary{},errors.New("response capture lacks HTTP header boundary")}
  body:=rs[cut+4:]
  if bytes.Contains(body,[]byte(p.Marker))!=o.MarkerPresent{
   return EvidenceSummary{},errors.New("reported proof marker is not present in captured response")
  }
  if o.Status<100||o.Status>599{return EvidenceSummary{},errors.New("invalid HTTP response status")}
  markerInRequest:=bytes.Contains(rq,[]byte(p.Marker))
  receipt:=SampleReceipt{SampleID:o.SampleID,Kind:o.Kind,Persona:o.Persona,Status:o.Status,
   RequestSHA256:o.RequestSHA256,ResponseSHA256:o.ResponseSHA256,
   MarkerPresent:o.MarkerPresent,MarkerInRequest:markerInRequest,
   Truncated:o.Truncated,ObservedAt:o.ObservedAt}
  summary.Receipts=append(summary.Receipts,receipt)
  if o.Kind=="candidate"{
   summary.Candidates++
   if o.MarkerPresent&&!markerInRequest&&o.Status>=200&&o.Status<300&&!o.Truncated{summary.ConsistentCandidates++}
  }else{
   summary.Controls++
   if !o.MarkerPresent&&o.Status>=200&&o.Status<500&&!o.Truncated{summary.ConsistentControls++}
  }
 }
 if summary.ConsistentCandidates==summary.Candidates&&
 summary.ConsistentControls==summary.Controls&&summary.Candidates>=2&&summary.Controls>=2{
  summary.Outcome="repeated_candidate_with_negative_controls"
 }else{summary.Outcome="inconclusive_or_failed_control"}
 return summary,nil
}
func (runner Runner) Run(ctx context.Context,p Plan,policy bunnyguard.Policy)(EvidenceSummary,error){
 if err:=Validate(p,policy);err!=nil{return EvidenceSummary{},err}
 if len(runner.EncryptionKey)!=32{return EvidenceSummary{},errors.New("trusted evidence encryption key required")}
 root:=runner.Root
 if root==""{return EvidenceSummary{},errors.New("explicit evidence destination required")}
 if len(root)>2048{return EvidenceSummary{},errors.New("evidence path too long")}
 if err:=os.MkdirAll(root,0700);err!=nil{return EvidenceSummary{},err}
 dir:=filepath.Join(root,p.RunID)
 if err:=os.Mkdir(dir,0700);err!=nil{return EvidenceSummary{},err}
 source,err:=Generate(p)
 if err!=nil{return EvidenceSummary{},err}
 scriptPath:=filepath.Join(dir,"scenario.py")
 if err:=os.WriteFile(scriptPath,source,0600);err!=nil{return EvidenceSummary{},err}
 planBytes,err:=json.MarshalIndent(p,"","  ")
 if err!=nil{return EvidenceSummary{},err}
 if err:=os.WriteFile(filepath.Join(dir,"plan.json"),planBytes,0600);err!=nil{return EvidenceSummary{},err}
 exe:=runner.Python
 if exe==""{
  if e,found:=exec.LookPath("python3");found==nil{exe=e
  }else if e,found:=exec.LookPath("python");found==nil{exe=e}
 }
 if exe==""{return EvidenceSummary{},errors.New("Python 3 interpreter unavailable")}
 origin,_:=normalizedOrigin(p.Origin)
 proxyURL:="none"
 if strings.HasPrefix(origin,"https://"){
  proxy,err:=bunnyegress.New(bunnyegress.Config{
   Origins:[]string{origin},MaxTunnels:len(p.Cases),
  })
  if err!=nil{return EvidenceSummary{},err}
  address,err:=proxy.Start()
  if err!=nil{return EvidenceSummary{},err}
  defer proxy.Close()
  proxyURL=address
 }
 outputPath:=filepath.Join(dir,"_unencrypted_capture.json")
 defer os.Remove(outputPath)
 timeout,cancel:=context.WithTimeout(ctx,180*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(timeout,exe,"-I","-S",scriptPath,"--out",outputPath,proxyURL)
 cmd.Dir=dir
 cmd.Env=[]string{"PATH="+os.Getenv("PATH"),"PYTHONNOUSERSITE=1","PYTHONDONTWRITEBYTECODE=1"}
 if home:=os.Getenv("SYSTEMROOT");home!=""{cmd.Env=append(cmd.Env,"SYSTEMROOT="+home)}
 // Each test cookie must be preprovisioned in a trusted keyring. The generated
 // Python source contains persona aliases but never cookie values.
 seen:=map[string]bool{}
 for _,c:=range p.Cases{
  if c.Persona==""||seen[c.Persona]{continue}
  if runner.Secrets==nil{return EvidenceSummary{},errors.New("trusted persona-cookie resolver required")}
  cookie,e:=runner.Secrets.Resolve(ctx,c.Persona,"session_cookie")
  if e!=nil||cookie==""||len(cookie)>4096||strings.ContainsAny(cookie,"\r\n"){
   return EvidenceSummary{},errors.New("approved test persona session cookie unavailable")
  }
  cmd.Env=append(cmd.Env,"BUNNY_PROOF_COOKIE_"+strings.ToUpper(c.Persona)+"="+cookie)
  seen[c.Persona]=true
 }
 var stdout,stderr bytes.Buffer
 cmd.Stdout=&stdout
 cmd.Stderr=&stderr
 if err:=cmd.Run();err!=nil{return EvidenceSummary{},errors.New("generated Python evidence run failed; no success asserted")}
 captured,err:=os.ReadFile(outputPath)
 if err!=nil{return EvidenceSummary{},errors.New("generated runner returned no raw transcript")}
 summary,err:=validateTrace(captured,p)
 if err!=nil{return EvidenceSummary{},err}
 stored,err:=bunnyartifact.Store(dir,"transcript","http_proof",captured,runner.EncryptionKey)
 if err!=nil{return EvidenceSummary{},err}
 summary.ScriptFile="scenario.py"
 summary.ScriptSHA256=SHA(source)
 summary.PlanSHA256=SHA(planBytes)
 summary.RawEvidenceFile=stored.File
 report,err:=json.MarshalIndent(summary,"","  ")
 if err!=nil{return EvidenceSummary{},err}
 if err:=os.WriteFile(filepath.Join(dir,"validation.json"),report,0600);err!=nil{return EvidenceSummary{},err}
 var markdown strings.Builder
 fmt.Fprintf(&markdown,"# BunnyMind captured Python proof: %s\n\n",p.RunID)
 fmt.Fprintf(&markdown,"**Engagement:** %s  \n**Result:** %s  \n**Script:** scenario.py (SHA-256 %s)  \n**Evidence:** %s (SHA-256 %s)\n\n",p.EngagementID,summary.Outcome,summary.ScriptSHA256,summary.RawEvidenceFile,summary.RawEvidenceSHA256)
 markdown.WriteString("## Captured cases\n\n| Sample | Kind | HTTP status | Marker in observed body | Truncated | Request SHA-256 | Response SHA-256 |\n|---|---|---:|---|---|---|---|\n")
 for _,r:=range summary.Receipts{
  fmt.Fprintf(&markdown,"| %s | %s | %d | %t | %t | %s | %s |\n",
   r.SampleID,r.Kind,r.Status,r.MarkerPresent,r.Truncated,r.RequestSHA256,r.ResponseSHA256)
 }
 markdown.WriteString("\n## Captured evidence and verification\n\nThe full, private HTTP request/response observations are encrypted in the referenced vault artifact. Repeated candidate markers with negative controls are an auditable signal but **not independently confirmed security impact**. Response bodies are capped at 64 KiB; a truncated observation cannot satisfy the consistency check.\n\nFor confidential triage, explicitly decrypt the vault locally using the operator's OS-keyring key. Avoid attaching raw private data in public issues or untrusted channels.\n")
 if err:=os.WriteFile(filepath.Join(dir,"report.md"),[]byte(markdown.String()),0600);err!=nil{return EvidenceSummary{},err}
 note:=[]byte("BunnyMind Python proof capture\n\nscenario.py: exact generated Python source\nplan.json: selected approved tests\nvalidation.json: redacted observations and SHA-256 digests\ntranscript.enc: AES-256-GCM full captured request and response bytes, up to 64 KiB response body per sample\n\nThis evidence is not independently verified to prove a vulnerability. Decrypt only in an authorized triage environment.\n")
 if err:=os.WriteFile(filepath.Join(dir,"README.txt"),note,0600);err!=nil{return EvidenceSummary{},err}
 return summary,nil
}
