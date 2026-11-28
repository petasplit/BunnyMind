package bunnyprogram

import (
 "strings"
 "testing"
)

func TestFiniteProgramScopesExpandTLDsWithoutWildcards(t *testing.T){
 got:=ExactWebOrigins([]string{
  "www.doctolib.(fr|de|it) Web application",
  "pro.doctolib.(fr|de|it) Web application",
  "*.doctolib.(fr|de|it|com|net) Web application",
  "https://apps.apple.com/fr/app/doctolib/id925339063 Mobile application",
  "https://api.example.org API",
 })
 all:=strings.Join(got," ")
 if len(got)!=7||!strings.Contains(all,"https://www.doctolib.fr")||
  !strings.Contains(all,"https://pro.doctolib.it")||
  strings.Contains(all,"https://apple.com"){
  t.Fatalf("unexpected finite scope expansion: %#v",got)
 }
}
func TestIndependentGuardIntersectionAndShorthandExclusions(t *testing.T){
 finite:=[]string{
  "https://www.doctolib.fr","https://pro.doctolib.fr",
  "https://community.doctolib.fr","https://other.example.org",
 }
 reviewed:=[]string{"https://www.doctolib.fr","https://pro.doctolib.fr","https://community.doctolib.fr"}
 excluded:=[]string{"community.doctolib.com | .fr | .de | .it","Any raw IP address"}
 got:=ApprovedIntersection(finite,reviewed,excluded)
 if len(got)!=2||got[0]!="https://www.doctolib.fr"||got[1]!="https://pro.doctolib.fr"{
  t.Fatalf("excluded or unapproved asset leaked into automatic seeds: %#v",got)
 }
}
