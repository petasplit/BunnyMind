package bunnyprogram

import (
 "net"
 "net/url"
 "sort"
 "strings"
)

// ExactWebOrigins extracts explicit first-party web hostnames from scope rows.
// A wildcard scope is deliberately NOT expanded into arbitrary subdomains.
// Parenthesized *finite TLD alternatives* are enumerated as exact hostnames,
// and mobile app-store links are not accepted as scan seeds.
func ExactWebOrigins(entries []string)[]string {
 seen:=map[string]bool{}
 for _,entry:=range entries{
  if strings.Contains(strings.ToLower(entry),"mobile application"){continue}
  fields:=strings.Fields(entry)
  if len(fields)==0{continue}
  item:=fields[0]
  if strings.HasPrefix(item,"*.")||strings.Contains(item,"*"){continue}
  if strings.Contains(item,"(")&&strings.Contains(item,")"){
   a:=strings.Index(item,"(");b:=strings.Index(item[a:],")")
   if b<=0{continue}
   b+=a
   options:=strings.Split(item[a+1:b],"|")
   if len(options)<2||len(options)>8{continue}
   for _,suffix:=range options{
    if len(suffix)<2||len(suffix)>10{continue}
    host:=item[:a]+suffix+item[b+1:]
    addExact(seen,host)
   }
   continue
  }
  addExact(seen,item)
 }
 list:=[]string{}
 for v:=range seen{list=append(list,v)}
 sort.Strings(list)
 if len(list)>32{list=list[:32]}
 return list
}
func addExact(seen map[string]bool,input string){
 if !strings.Contains(input,"://"){input="https://"+input}
 u,err:=url.Parse(input)
 if err!=nil||u==nil||u.Scheme!="https"||u.User!=nil||
  u.Hostname()==""||u.Port()!=""||u.RawQuery!=""||u.Fragment!=""||
  (u.Path!=""&&u.Path!="/")||strings.ContainsAny(u.Hostname(),"()|*\\@")||
  net.ParseIP(u.Hostname())!=nil{return}
 hostname:=strings.ToLower(u.Hostname())
 if hostname=="apps.apple.com"||hostname=="play.google.com"{return}
 seen["https://"+hostname]=true
}
// ApprovedIntersection intersects finite web entries with an independently
// reviewed operator manifest. Exclusions are an additional denylist; program
// hints NEVER create permissions beyond the manifest. Pattern-based policy
// exceptions must still be reviewed by the operator before the manifest is set.
func ApprovedIntersection(exact []string,operatorOrigins []string,exclusions []string)[]string{
 allowed:=map[string]bool{}
 for _,item:=range operatorOrigins{allowed[strings.ToLower(strings.TrimSuffix(item,"/"))]=true}
 out:=[]string{}
 for _,origin:=range exact{
  if !allowed[origin]{continue}
  u,err:=url.Parse(origin)
  if err!=nil||u.Hostname()==""{continue}
  host:=strings.ToLower(u.Hostname())
  denied:=false
  for _,raw:=range exclusions{
   line:=strings.ToLower(raw)
   if strings.Contains(line,host){denied=true;break}
   // A program may abbreviate multi-TLD exclusions:
   // community.doctolib.com | .fr | .de | .it
   labels:=strings.Split(host,".")
   if len(labels)==3&&strings.Contains(line,labels[0]+"."+labels[1]+".")&&
    strings.Contains(line,"."+labels[2]) {
    denied=true;break
   }
  }
  if !denied{out=append(out,origin)}
 }
 return out
}
