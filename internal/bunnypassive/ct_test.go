package bunnypassive

import (
 "strings"
 "testing"
)

func TestScopeRootsExpandOnlyRegistrableDomains(t *testing.T){
 entries:=[]string{
  "",
  "www.doctolib.(fr|de|it) Web application",
  "*.doctolib.(fr|de|it|com|net)",
  "*.siilo.com",
  "https://apps.apple.com/fr/app/doctolib/id925339063",
  "not-a-domain",
 }
 roots:=RootsForProgram(entries)
 if len(roots)!=6{t.Fatalf("expected six registrable scope roots, got %#v",roots)}
 all:=strings.Join(roots," ")
 if !strings.Contains(all,"doctolib.fr")||!strings.Contains(all,"doctolib.de")||
  !strings.Contains(all,"siilo.com"){t.Fatalf("wanted real registrable domains, got %#v",roots)}
 for _,r:=range roots{if strings.HasSuffix(r,"apple.com")||strings.Contains(r,"("){t.Fatalf("mobile-store URL promoted to CT domain: %s",r)}}
}
func TestPassiveCandidateFiltering(t *testing.T){
 raw:=[]byte(`[
 {"name_value":"api.example.org\\nwww.example.org"},
 {"name_value":"*.test.example.org"},
 {"name_value":"evil-example.org"},
 {"name_value":"api.example.org"},
 {"name_value":"example.org.evil.invalid"}
]`)
 // JSON escape in fixture decodes to literal newline separating names.
 raw=[]byte(strings.ReplaceAll(string(raw),`\\n`,`\n`))
 got,err:=FilterCTNames("example.org",raw,10)
 if err!=nil{t.Fatal(err)}
 want:=[]string{"api.example.org","test.example.org","www.example.org"}
 if len(got)!=len(want){t.Fatalf("filtered candidate mismatch %#v",got)}
 for i,n:=range want{if got[i]!=n{t.Fatalf("expected %s at %d got %#v",n,i,got)}}
}
func TestInvalidPassiveDestinations(t *testing.T){
 for _,domain:=range []string{"localhost","127.0.0.1","https://example.org","internal","metadata.google.internal","evil.com:443"}{
  _,err:=ValidDomain(domain)
  if err==nil{t.Fatalf("unexpected accepted domain %q",domain)}
 }
}
func TestMalformedCTReturnsError(t *testing.T){
 if _,err:=FilterCTNames("example.org",[]byte("{broken"),100);err==nil{t.Fatal("invalid CT JSON accepted")}
}
