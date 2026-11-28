// Package bunnyjsruntime invokes BunnyMind's bundled, static-only
// TypeScript AST analyzer on private temporary JavaScript files. No target
// code is executed. Parsed endpoint metadata is aggressively bounded.
package bunnyjsruntime

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net/url"
 "os"
 "os/exec"
 "path/filepath"
 "strings"
 "time"
)
type Endpoint struct {
 Path string `json:"path"`
 Method string `json:"method"`
 Source string `json:"source"`
 Line int `json:"line"`
 Column int `json:"column"`
 ReferenceSHA256 string `json:"reference_sha256"`
 Original *Original `json:"original,omitempty"`
}
type Original struct{
 SourceName string `json:"source_name"`
 SourceSHA256 string `json:"source_sha256"`
 Line int `json:"line"`
 Column int `json:"column"`
}
type SourceMap struct {
 Status string `json:"status"`
 MapSHA256 string `json:"map_sha256,omitempty"`
 SourcesCount int `json:"sources_count,omitempty"`
 MappingsSegments int `json:"mappings_segments,omitempty"`
 Attributed int `json:"attributed,omitempty"`
}
type Report struct{
 Version int `json:"version"`
 Origin string `json:"origin"`
 SourceSHA256 string `json:"source_sha256"`
 ParseErrors []string `json:"parse_errors"`
 ASTNodesVisited int `json:"ast_nodes_visited"`
 Endpoints []Endpoint `json:"endpoints"`
 SourceMap SourceMap `json:"source_map"`
 Limitation string `json:"limitation"`
}
func binary()(string,error){
 configured:=strings.TrimSpace(os.Getenv("BUNNY_JS_AST_BIN"))
 if configured==""{
  exe,err:=os.Executable()
  if err!=nil{return "",err}
  configured=filepath.Join(filepath.Dir(exe),"BunnyMind-js-ast-windows-x64.exe")
 }
 if len(configured)>2048{return "",errors.New("AST helper path too long")}
 info,err:=os.Lstat(configured)
 if err!=nil||!info.Mode().IsRegular(){return "",errors.New("trusted AST helper executable not present")}
 return configured,nil
}
func Available()bool{
 _,err:=binary()
 return err==nil
}
func Valid(report Report,origin string)error {
 if report.Version!=1||report.Origin!=origin||len(report.SourceSHA256)!=64||
  len(report.Endpoints)>160||len(report.ParseErrors)>12||report.ASTNodesVisited>170001{
  return errors.New("untrusted AST parser returned invalid metadata")
 }
 for _,e:=range report.Endpoints{
  if len(e.Path)<1||len(e.Path)>2048||!strings.HasPrefix(e.Path,"/")||
   strings.HasPrefix(e.Path,"//")||strings.ContainsAny(e.Path,"\\?#")||
   strings.Contains(e.Path,"..")||e.Line<1||e.Column<1{
   return errors.New("AST parser returned unsafe or unbounded endpoint")
  }
  switch e.Method{
  case "GET","POST","PUT","PATCH","DELETE","HEAD","REFERENCE":default:
   return errors.New("AST parser returned unexpected method")
  }
 }
 return nil
}
type limited struct{
 data bytes.Buffer
 max int
 overflow bool
}
func (l *limited)Write(p []byte)(int,error){
 old:=len(p)
 room:=l.max-l.data.Len()
 if room<0{room=0}
 if room<len(p){l.overflow=true}
 if room>len(p){room=len(p)}
 if room>0{_,_=l.data.Write(p[:room])}
 return old,nil
}
func Analyze(ctx context.Context,origin,source string)(Report,error){
 parsed,err:=url.Parse(origin)
 if err!=nil||parsed==nil||parsed.Scheme!="https"||parsed.User!=nil||parsed.Hostname()==""||
  parsed.RawQuery!=""||parsed.Fragment!=""||(parsed.Path!=""&&parsed.Path!="/"){
  return Report{},errors.New("AST analyzer requires an exact authorized HTTPS origin")
 }
 if len(source)==0||len(source)>512*1024{return Report{},errors.New("JS source exceeds static parser bound")}
 exe,err:=binary()
 if err!=nil{return Report{},err}
 temp,err:=os.MkdirTemp("","bunnymind-js-ast-")
 if err!=nil{return Report{},err}
 defer os.RemoveAll(temp)
 if err:=os.Chmod(temp,0700);err!=nil{return Report{},err}
 script:=filepath.Join(temp,"bundle.js")
 if err:=os.WriteFile(script,[]byte(source),0600);err!=nil{return Report{},err}
 timeout,cancel:=context.WithTimeout(ctx,12*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(timeout,exe,"--file",script,"--origin",parsed.Scheme+"://"+parsed.Host)
 cmd.Dir=temp
 cmd.Env=[]string{"PATH="+os.Getenv("PATH"),"HOME="+os.Getenv("HOME")}
 if root:=os.Getenv("SYSTEMROOT");root!=""{cmd.Env=append(cmd.Env,"SYSTEMROOT="+root)}
 var out,stderr limited
 out.max=65536;stderr.max=2048
 cmd.Stdout=&out;cmd.Stderr=&stderr
 if err:=cmd.Run();err!=nil{
  return Report{},fmt.Errorf("offline AST helper unavailable: %w",err)
 }
 if out.overflow||stderr.overflow{return Report{},errors.New("AST helper exceeded its output limit")}
 var report Report
 dec:=json.NewDecoder(bytes.NewReader(out.data.Bytes()))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(&report);err!=nil{return Report{},err}
 if err:=Valid(report,parsed.Scheme+"://"+parsed.Host);err!=nil{return Report{},err}
 actual:=sha256.Sum256([]byte(source))
 if report.SourceSHA256!=hex.EncodeToString(actual[:]){return Report{},errors.New("AST report source hash differs from input")}
 return report,nil
}
