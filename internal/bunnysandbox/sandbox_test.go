package bunnysandbox

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func example(t *testing.T)Spec{
 t.Helper()
 return Spec{JobID:"js_inspection",Image:"local/bunnymind-js@sha256:"+strings.Repeat("a",64),
  WorkingDir:t.TempDir(),Arguments:[]string{"node","/input/analyze.js","--offline"},
  TimeoutSeconds:60,MemoryMB:512,CPUPercent:100,PIDs:32,
 }
}
func TestDockerArgumentsNeverAllowNetworkOrHostWrites(t *testing.T){
 spec:=example(t)
 args,err:=BuildDockerArgs(spec)
 if err!=nil{t.Fatal(err)}
 txt:=strings.Join(args," ")
 for _,required:=range []string{"--network=none","--read-only","--cap-drop=ALL",
  "--security-opt=no-new-privileges:true","--pull=never","--pids-limit=32",
  "--memory=512m","--cpus=1.00","--user=65534:65534","dst=/input,readonly"}{
  if !strings.Contains(txt,required){t.Fatalf("sandbox missing %q: %s",required,txt)}
 }
 for _,forbidden:=range []string{"--privileged ","--network=host","/var/run/docker.sock"}{
  if strings.Contains(txt,forbidden){t.Fatalf("host breakout option present: %s",forbidden)}
 }
}
func TestRejectUnsafeSandboxProfiles(t *testing.T){
 good:=example(t)
 bad:=good;bad.Image="ubuntu:latest"
 if _,err:=BuildDockerArgs(bad);err==nil{t.Fatal("unpinned mutable image accepted")}
 bad=good;bad.Arguments=[]string{"--privileged"}
 if _,err:=BuildDockerArgs(bad);err==nil{t.Fatal("privileged option accepted")}
 bad=good;bad.TimeoutSeconds=3600
 if _,err:=BuildDockerArgs(bad);err==nil{t.Fatal("unbounded timeout accepted")}
 bad=good;bad.MemoryMB=6000
 if _,err:=BuildDockerArgs(bad);err==nil{t.Fatal("unbounded RAM accepted")}
 bad=good;bad.WorkingDir="../relative"
 if _,err:=BuildDockerArgs(bad);err==nil{t.Fatal("relative source mount accepted")}
 link:=filepath.Join(t.TempDir(),"symlink")
 if err:=os.Symlink(good.WorkingDir,link);err==nil{
  bad=good;bad.WorkingDir=link
  if _,err:=BuildDockerArgs(bad);err==nil{t.Fatal("symlink source mount accepted")}
 }
}
func TestLoadSpecRejectsUntrustedFields(t *testing.T){
 good:=example(t)
 dir:=t.TempDir()
 file:=filepath.Join(dir,"profile.json")
 raw,_:=json.Marshal(good)
 if err:=os.WriteFile(file,raw,0600);err!=nil{t.Fatal(err)}
 if _,err:=LoadSpec(file);err!=nil{t.Fatal(err)}
 raw=[]byte(strings.TrimRight(string(raw),"}")+",\"network\":\"host\"}")
 if err:=os.WriteFile(file,raw,0600);err!=nil{t.Fatal(err)}
 if _,err:=LoadSpec(file);err==nil{t.Fatal("unknown sandbox escape field accepted")}
}
