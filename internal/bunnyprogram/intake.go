// Package bunnyprogram reads public bug-bounty program descriptions into a
// reviewable scope proposal. It never grants active testing permission.
package bunnyprogram

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "net/url"
 "regexp"
 "strings"
 "time"

 "golang.org/x/net/html"
 "github.com/enowdev/antares/internal/bunnynet"
)

const MaxProgramHTML = 512*1024
var slugRE=regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{1,110}$`)

type Snapshot struct {
 ProgramURL string `json:"program_url"`
 Title string `json:"title"`
 RetrievedUTC string `json:"retrieved_utc"`
 PageSHA256 string `json:"page_sha256"`
 PageBytes int `json:"page_bytes"`
 ScopeEntries []string `json:"scope_entries"`
 ProposedExactWebOrigins []string `json:"proposed_exact_web_origins"`
 ScopeProposalFile string `json:"scope_proposal_file,omitempty"`
 OutOfScope []string `json:"out_of_scope"`
 TestingPrecautions []string `json:"testing_precautions"`
 Notes []string `json:"notes"`
 RequiresReview bool `json:"requires_review"`
 ActiveScanningStarted bool `json:"active_scanning_started"`
 Status string `json:"status"`
}
func AllowedProgramURL(raw string)(string,error){
 u,err:=url.Parse(strings.TrimSpace(raw))
 if err!=nil||u==nil||u.Opaque!=""||u.User!=nil||u.Scheme!="https"||
  !strings.EqualFold(u.Hostname(),"yeswehack.com")||u.Port()!=""||
  u.RawQuery!=""||u.Fragment!=""{
  return "",errors.New("program intake accepts only an exact HTTPS YesWeHack public program URL")
 }
 slug:=strings.TrimPrefix(u.EscapedPath(),"/programs/")
 if !strings.HasPrefix(u.Path,"/programs/")||!slugRE.MatchString(slug){
  return "",errors.New("program URL must be /programs/<public-slug> without redirects")
 }
 return "https://yeswehack.com/programs/"+slug,nil
}
func Fetch(ctx context.Context,raw string)(Snapshot,error){
 uri,err:=AllowedProgramURL(raw)
 if err!=nil{return Snapshot{},err}
 reader,err:=bunnynet.New(bunnynet.Policy{Origins:[]string{"https://yeswehack.com"}})
 if err!=nil{return Snapshot{},err}
 result,body,err:=reader.ReadDocument(ctx,uri,"BunnyMind-ProgramIntake/0.33 (public policy review)",MaxProgramHTML)
 if err!=nil{return Snapshot{},fmt.Errorf("public program retrieval failed: %w",err)}
 if result.Status!=200||result.Truncated||!strings.Contains(strings.ToLower(result.ContentType),"html"){
  return Snapshot{},fmt.Errorf("program page not verified as complete HTML (status %d, truncated %t)",result.Status,result.Truncated)
 }
 out,err:=Parse(uri,body)
 if err!=nil{return Snapshot{},err}
 return out,nil
}

type block struct{ Tag, Text string }
func normalize(s string)string{return strings.Join(strings.Fields(strings.ReplaceAll(s,"\u00a0"," "))," ")}
func nodeText(n *html.Node)string{
 var b strings.Builder
 var walk func(*html.Node)
 walk=func(c *html.Node){
  if c.Type==html.ElementNode {
   switch c.Data {case "script","style","noscript","svg","template":return}
  }
  if c.Type==html.TextNode{b.WriteString(c.Data);b.WriteByte(' ')}
  for child:=c.FirstChild;child!=nil;child=child.NextSibling{walk(child)}
 }
 walk(n)
 return normalize(b.String())
}
func isBlock(tag string)bool{
 switch tag {
 case "h1","h2","h3","h4","h5","h6","p","tr","li","dt","dd":return true
 }
 return false
}
func collectBlocks(root *html.Node)[]block{
 out:=make([]block,0,256)
 var walk func(*html.Node)
 walk=func(n *html.Node){
  if n.Type==html.ElementNode{
   switch n.Data {case "script","style","noscript","svg","template":return}
   if isBlock(n.Data){
    v:=nodeText(n)
    if v!=""{out=append(out,block{Tag:n.Data,Text:v})}
    // Never double-count all of a table row via individual cells.
    return
   }
  }
  for c:=n.FirstChild;c!=nil;c=c.NextSibling{walk(c)}
 }
 walk(root)
 return out
}
func cleanEntry(s string)string{
 s=normalize(s)
 if i:=strings.Index(s," | ");i>0{s=s[:i]}
 // Card rows sometimes contain CVSS labels directly after the asset.
 for _,label:=range []string{" Web application"," Mobile application"," API "," Application "," €"}{
  if at:=strings.Index(s,label);at>0{s=s[:at]}
 }
 return strings.TrimSpace(s)
}
func candidateEntry(s string)bool{
 s=cleanEntry(s)
 if len(s)<6||len(s)>240{return false}
 l:=strings.ToLower(s)
 return strings.HasPrefix(l,"https://")||strings.HasPrefix(l,"http://")||
  strings.HasPrefix(l,"*.")||strings.HasPrefix(l,"www.")||
  strings.HasPrefix(l,"pro.")||strings.Contains(l,".doctolib.")||
  strings.Contains(l,".siilo.")
}
func appendUnique(in []string,s string,max int)[]string{
 if s==""||len(in)>=max{return in}
 for _,v:=range in{if v==s{return in}}
 return append(in,s)
}
func heading(tag string)bool{return len(tag)>0&&tag[0]=='h'}
func classifyHeading(s string)string{
 h:=strings.ToLower(normalize(s))
 switch {
 case h=="scopes"||h=="scope"||h=="in scope"||h=="in-scope":return "scope"
 case h=="out of scopes"||h=="out of scope"||h=="out-of-scope":return "excluded"
 case strings.Contains(h,"testing precautions")||strings.Contains(h,"testing rules"):return "precautions"
 case strings.Contains(h,"eligibility and rules")||h=="program rules":return "rules"
 case h=="vulnerability types"||h=="qualifying vulnerabilities"||h=="non-qualifying vulnerabilities":return "end"
 default:return ""
 }
}
func Parse(programURL string,body []byte)(Snapshot,error){
 uri,err:=AllowedProgramURL(programURL)
 if err!=nil{return Snapshot{},err}
 if len(body)<40||len(body)>MaxProgramHTML{return Snapshot{},errors.New("incomplete or oversized program source")}
 root,err:=html.Parse(strings.NewReader(string(body)))
 if err!=nil{return Snapshot{},errors.New("invalid program document HTML")}
 h:=sha256.Sum256(body)
 out:=Snapshot{ProgramURL:uri,RetrievedUTC:time.Now().UTC().Format(time.RFC3339Nano),
  PageSHA256:hex.EncodeToString(h[:]),PageBytes:len(body),
  ScopeEntries:[]string{},OutOfScope:[]string{},TestingPrecautions:[]string{},Notes:[]string{},
  RequiresReview:true,ActiveScanningStarted:false,Status:"public_program_documentation_review",
 }
 bs:=collectBlocks(root)
 // Every section starts at a real HTML heading, not arbitrary page text or
 // a nav label like "Scopes 9"; this avoids elevating unrelated URLs.
 section:=""
 for _,b:=range bs{
  if heading(b.Tag){
   if out.Title==""&&b.Tag=="h1"{out.Title=b.Text}
   if k:=classifyHeading(b.Text);k!=""{section=k;continue}
   if section=="scope"||section=="excluded"||section=="precautions"||section=="rules"{
    section=""
   }
  }
  switch section{
  case "scope":
   item:=cleanEntry(b.Text)
   if candidateEntry(item){out.ScopeEntries=appendUnique(out.ScopeEntries,item,64)}
  case "excluded":
   if len(b.Text)>=5&&len(b.Text)<=300{out.OutOfScope=appendUnique(out.OutOfScope,b.Text,96)}
  case "precautions","rules":
   if len(b.Text)>=12&&len(b.Text)<=700{out.TestingPrecautions=appendUnique(out.TestingPrecautions,b.Text,48)}
  }
  if strings.Contains(b.Text,"BugBounty/42 (YWH)"){
   out.Notes=appendUnique(out.Notes,"Program mentions User-Agent: BugBounty/42 (YWH)",5)
  }
  low:=strings.ToLower(b.Text)
  if strings.Contains(low,"10 requests per second"){
   out.Notes=appendUnique(out.Notes,"Program mentions maximum 10 requests per second; use a gentler default.",5)
  }
 }
 out.ProposedExactWebOrigins=ExactWebOrigins(out.ScopeEntries)
 if len(out.ScopeEntries)==0{
  out.Notes=appendUnique(out.Notes,"No machine-readable scope rows verified: review the program in a browser; no asset is approved automatically.",6)
 }
 out.Notes=appendUnique(out.Notes,"Entries are a review proposal, not a BunnyGuard policy. Wildcards, exclusions, third-party assets and changing program rules require reconciliation before active testing.",6)
 return out,nil
}
