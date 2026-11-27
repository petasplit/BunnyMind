// Package bunnyhar extracts non-secret, scope-filtered metadata from locally
// supplied HAR captures. It never makes HTTP requests or persists credentials.
package bunnyhar

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

const (
	MaxFileBytes = 8 << 20
	MaxEntries = 10000
	MaxEndpoints = 200
)
var methods = map[string]bool{
	"GET":true,"HEAD":true,"OPTIONS":true,"POST":true,"PUT":true,"PATCH":true,"DELETE":true,
}
type Endpoint struct {
	ID string `json:"id"`
	Method string `json:"method"`
	Origin string `json:"origin"`
	Requests int `json:"requests"`
	AuthenticatedRequests int `json:"authenticated_requests"`
	StatusClasses map[string]int `json:"status_classes"`
}
type Summary struct {
	TotalEntries int `json:"total_entries"`
	InScope int `json:"in_scope"`
	OutOfScope int `json:"out_of_scope"`
	Invalid int `json:"invalid"`
	AuthenticatedRequests int `json:"authenticated_requests"`
	Methods map[string]int `json:"methods"`
	Origins map[string]int `json:"origins"`
	StatusClasses map[string]int `json:"status_classes"`
	UniqueEndpoints int `json:"unique_endpoints"`
	ShownEndpoints int `json:"shown_endpoints"`
	Endpoints []Endpoint `json:"endpoints"`
	Disclaimer string `json:"disclaimer"`
}
type harEnvelope struct {
	Log struct {
		Entries []struct {
			Request struct {
				URL string `json:"url"`
				Method string `json:"method"`
				Headers []struct {Name string `json:"name"`} `json:"headers"`
				Cookies []json.RawMessage `json:"cookies"`
			} `json:"request"`
			Response struct {Status int `json:"status"`} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

func originAllowed(raw string, allow map[string]bool) (*url.URL,string,bool) {
	u,err:=url.Parse(raw)
	if err!=nil||u==nil||u.User!=nil||u.Opaque!=""||
		(u.Scheme!="https"&&u.Scheme!="http")||u.Hostname()==""||
		u.Fragment!=""{return nil,"",false}
	origin:=strings.ToLower(u.Scheme+"://"+u.Host)
	return u,origin,allow[origin]
}
func statusClass(status int) string {
	if status>=100&&status<=599{return fmt.Sprintf("%dxx",status/100)}
	return "unknown"
}
// Analyze validates a HAR file size, parses its exchanges and emits only
// bounded endpoint fingerprints, status aggregates and auth-presence counters.
// Header values, cookies, bodies, full URLs and query parameters are NEVER
// copied into the result. Callers must provide explicit allowed origins.
func Analyze(r io.Reader, allowedOrigins []string) (Summary,error) {
	if len(allowedOrigins)==0||len(allowedOrigins)>100{
		return Summary{},errors.New("1..100 approved origins required")
	}
	allow:=map[string]bool{}
	for _,s:=range allowedOrigins{
		u,err:=url.Parse(s)
		if err!=nil||u==nil||(u.Scheme!="https"&&u.Scheme!="http")||
		   u.Hostname()==""||u.User!=nil||u.Opaque!=""||
		   (u.Path!=""&&u.Path!="/")||u.RawQuery!=""||u.Fragment!="" {
			return Summary{},errors.New("invalid allowed origin")
		}
		allow[strings.ToLower(u.Scheme+"://"+u.Host)]=true
	}
	raw,err:=io.ReadAll(io.LimitReader(r,MaxFileBytes+1))
	if err!=nil{return Summary{},err}
	if len(raw)>MaxFileBytes{return Summary{},errors.New("HAR exceeds 8 MiB limit")}
	var doc harEnvelope
	if err:=json.Unmarshal(raw,&doc);err!=nil{return Summary{},fmt.Errorf("invalid HAR JSON: %w",err)}
	if len(doc.Log.Entries)>MaxEntries{return Summary{},errors.New("HAR exceeds 10000 exchanges")}
	s:=Summary{
		TotalEntries:len(doc.Log.Entries),Methods:map[string]int{},
		Origins:map[string]int{},StatusClasses:map[string]int{},
		Endpoints:[]Endpoint{},
		Disclaimer:"Imported HAR metadata is caller-supplied context, not proof of a fresh network request or a verified vulnerability. No credentials, URLs, request bodies or response bodies are retained.",
	}
	aggregated:=map[string]*Endpoint{}
	for _,record:=range doc.Log.Entries {
		m:=strings.ToUpper(strings.TrimSpace(record.Request.Method))
		if !methods[m]{s.Invalid++;continue}
		u,origin,valid:=originAllowed(record.Request.URL,allow)
		if !valid{
			// Distinguish invalid URLs from valid but out-of-scope origins.
			v,parseErr:=url.Parse(record.Request.URL)
			if parseErr!=nil||v==nil||v.Host==""||v.User!=nil||
			   (v.Scheme!="http"&&v.Scheme!="https"){s.Invalid++
			}else{s.OutOfScope++}
			continue
		}
		s.InScope++
		s.Methods[m]++
		s.Origins[origin]++
		sc:=statusClass(record.Response.Status)
		s.StatusClasses[sc]++
		auth:=len(record.Request.Cookies)>0
		for _,h:=range record.Request.Headers{
			if strings.EqualFold(h.Name,"authorization")||
			   strings.EqualFold(h.Name,"cookie")||
			   strings.EqualFold(h.Name,"proxy-authorization"){auth=true;break}
		}
		if auth{s.AuthenticatedRequests++}
		// Include only method + origin + path in a one-way fingerprint.
		// Query strings and fragments never reach the output.
		h:=sha256.Sum256([]byte(m+"\n"+origin+"\n"+u.EscapedPath()))
		key:="ep_"+hex.EncodeToString(h[:12])
		ep,ok:=aggregated[key]
		if !ok{
			ep=&Endpoint{ID:key,Method:m,Origin:origin,StatusClasses:map[string]int{}}
			aggregated[key]=ep
		}
		ep.Requests++
		if auth{ep.AuthenticatedRequests++}
		ep.StatusClasses[sc]++
	}
	keys:=make([]string,0,len(aggregated))
	for k:=range aggregated{keys=append(keys,k)}
	sort.Strings(keys)
	s.UniqueEndpoints=len(keys)
	for _,key:=range keys{
		if len(s.Endpoints)>=MaxEndpoints{break}
		s.Endpoints=append(s.Endpoints,*aggregated[key])
	}
	s.ShownEndpoints=len(s.Endpoints)
	return s,nil
}
