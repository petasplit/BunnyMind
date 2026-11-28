package bunnyprogram

import (
 "strings"
 "testing"
)

const sampleHTML=`<!doctype html><html><head><title>Example program</title></head><body>
<nav><a href="/other">Scopes</a></nav>
<h1>Example Public Bug Bounty</h1>
<h2>Testing precautions</h2>
<ul><li>Use the BugBounty/42 (YWH) string in your user-agent.</li>
<li>Avoid automated tools, or use them the gentle way (Max 10 requests per second).</li></ul>
<h2>Scopes</h2>
<table><tr><th>Scope</th><th>Type</th></tr>
<tr><td>www.doctolib.(fr|de|it)</td><td>Web application</td></tr>
<tr><td>*.doctolib.(fr|de|it|com|net)</td><td>Web application</td></tr>
<tr><td>https://apps.apple.com/fr/app/doctolib/id925339063</td><td>Mobile application IOS</td></tr>
</table>
<h3>Out of scopes</h3>
<ul><li>community.doctolib.com | .fr | .de | .it</li>
<li>Third-party assets linked from our products.</li>
<li>Any raw IPv4 / IPv6 address.</li></ul>
<h2>Vulnerability types</h2>
<p>SQL injection</p>
<script>window.fakeScope="https://evil.invalid";</script>
</body></html>`

func TestAllowedProgramURLStrict(t *testing.T){
 pass:=[]string{
  "https://yeswehack.com/programs/doctolib-public-bug-bounty-program",
  "https://yeswehack.com/programs/sample"
 }
 for _,url:=range pass{if _,err:=AllowedProgramURL(url);err!=nil{t.Fatalf("reject %s: %v",url,err)}}
 bad:=[]string{
  "http://yeswehack.com/programs/sample",
  "https://yeswehack.com.evil.org/programs/sample",
  "https://yeswehack.com/programs/../api",
  "https://yeswehack.com/programs/sample?token=x",
  "https://yeswehack.com/programs/%2fadmin",
  "https://yeswehack.com/other",
  "https://user:pass@yeswehack.com/programs/sample",
 }
 for _,url:=range bad{if _,err:=AllowedProgramURL(url);err==nil{t.Fatalf("unsafe URL accepted %s",url)}}
}
func TestParseProgramRespectsScopeAndExclusions(t *testing.T){
 out,err:=Parse("https://yeswehack.com/programs/sample",[]byte(sampleHTML))
 if err!=nil{t.Fatal(err)}
 if out.Title!="Example Public Bug Bounty"{t.Fatalf("wrong title %q",out.Title)}
 if len(out.ScopeEntries)!=3{t.Fatalf("wanted 3 in-scope rows, got %#v",out.ScopeEntries)}
 if len(out.OutOfScope)!=3{t.Fatalf("wanted 3 exclusion lines, got %#v",out.OutOfScope)}
 if !out.RequiresReview||out.ActiveScanningStarted{t.Fatal("scope incorrectly approved for active scanning")}
 if out.PageSHA256==""||out.PageBytes!=len(sampleHTML){t.Fatal("missing source provenance")}
 summary:=strings.Join(out.Notes," ")
 if !strings.Contains(summary,"BugBounty/42 (YWH)")||!strings.Contains(summary,"10 requests per second"){
  t.Fatalf("testing precautions lost: %#v",out.Notes)
 }
 for _,item:=range out.ScopeEntries {
  if strings.Contains(item,"evil")||strings.Contains(item,"community.doctolib.com"){
   t.Fatalf("untrusted or excluded URL promoted: %s",item)
  }
 }
}
func TestNoScopeVerifiedReportsReviewNeeded(t *testing.T){
 src:=[]byte("<html><body><h1>Title</h1><p>We will be back soon.</p></body></html>")
 out,err:=Parse("https://yeswehack.com/programs/sample",src)
 if err!=nil{t.Fatal(err)}
 if len(out.ScopeEntries)!=0||!strings.Contains(strings.Join(out.Notes," "),"No machine-readable scope"){
  t.Fatal("missing scope was not marked unverified")
 }
}
