// Package bunnysandbox executes operator-provisioned offline specialist jobs
// in an isolated Linux container. It never silently falls back to host shell.
package bunnysandbox

import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "os/exec"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "time"

 "github.com/enowdev/antares/internal/bunnyartifact"
)

var pinned=regexp.MustCompile(`^[a-z0-9][a-z0-9_.:/-]{0,140}@sha256:[a-f0-9]{64}$`)
var safeArg=regexp.MustCompile(`^[[:print:]]{1,256}$`)
type Spec struct{
 JobID string `json:"job_id"`
 Image string `json:"image"`
 WorkingDir string `json:"working_dir"`
 Arguments []string `json:"arguments"`
 TimeoutSeconds int `json:"timeout_seconds"`
 MemoryMB int `json:"memory_mb"`
 CPUPercent int `json:"cpu_percent"`
 PIDs int `json:"pids"`
}
type Receipt struct{
 JobID string `json:"job_id"`
 SpecSHA256 string `json:"spec_sha256"`
 ExitCode int `json:"exit_code"`
 OutputSHA256 string `json:"output_sha256"`
 OutputBytes int `json:"output_bytes"`
 EncryptedOutput bunnyartifact.Receipt `json:"encrypted_output"`
 DurationMS int64 `json:"duration_ms"`
 Outcome string `json:"outcome"`
 Limitation string `json:"limitation"`
}
func checkSpec(s Spec)error{
 if len(s.JobID)<2||len(s.JobID)>48||strings.ContainsAny(s.JobID,"/\\.\n\r")||
  !pinned.MatchString(s.Image)||len(s.Arguments)==0||len(s.Arguments)>24{
  return errors.New("sandbox requires named job, pinned image digest and bounded argv")
 }
 if s.TimeoutSeconds<1||s.TimeoutSeconds>300||s.MemoryMB<128||s.MemoryMB>2048||
  s.CPUPercent<10||s.CPUPercent>200||s.PIDs<4||s.PIDs>64 {
  return errors.New("sandbox resource limits exceed approved local bounds")
 }
 if !filepath.IsAbs(s.WorkingDir)||len(s.WorkingDir)>1800||
  strings.ContainsAny(s.WorkingDir,",\r\n"){return errors.New("workspace must be an absolute, safe path")}
 info,err:=os.Lstat(s.WorkingDir)
 if err!=nil||!info.IsDir()||info.Mode()&os.ModeSymlink!=0{return errors.New("sandbox input must be an existing directory, not a symlink")}
 for _,arg:=range s.Arguments{
  if !safeArg.MatchString(arg)||strings.ContainsAny(arg,"\r\n\x00")||
   strings.HasPrefix(arg,"--privileged")||strings.Contains(arg,"/var/run/docker.sock"){
   return errors.New("unsafe sandbox argv")
  }
 }
 return nil
}
func BuildDockerArgs(s Spec)([]string,error){
 if err:=checkSpec(s);err!=nil{return nil,err}
 mount:="type=bind,src="+filepath.Clean(s.WorkingDir)+",dst=/input,readonly"
 arguments:=[]string{
  "run","--rm","--pull=never","--network=none","--read-only",
  "--cap-drop=ALL","--security-opt=no-new-privileges:true",
  "--pids-limit="+strconv.Itoa(s.PIDs),
  "--memory="+strconv.Itoa(s.MemoryMB)+"m",
  "--cpus="+strconv.FormatFloat(float64(s.CPUPercent)/100.0,'f',2,64),
  "--user=65534:65534",
  "--mount="+mount,
  "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
  "--workdir=/input","--init",s.Image,
 }
 return append(arguments,s.Arguments...),nil
}
func LoadSpec(path string)(Spec,error){
 if path==""||len(path)>1800{return Spec{},errors.New("trusted sandbox spec path required")}
 info,err:=os.Lstat(path)
 if err!=nil||!info.Mode().IsRegular()||info.Size()>16384{return Spec{},errors.New("operator-owned sandbox JSON unavailable")}
 raw,err:=os.ReadFile(path)
 if err!=nil{return Spec{},err}
 var s Spec
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if err:=d.Decode(&s);err!=nil{return Spec{},err}
 if err:=checkSpec(s);err!=nil{return Spec{},err}
 return s,nil
}
func hash(raw []byte)string{d:=sha256.Sum256(raw);return hex.EncodeToString(d[:])}
type cappedWriter struct{
 limit int
 data []byte
 overflow bool
}
func (w *cappedWriter)Write(p []byte)(int,error){
 original:=len(p)
 free:=w.limit-len(w.data)
 if free>0 {
  if len(p)>free{w.data=append(w.data,p[:free]...)}else{w.data=append(w.data,p...)}
 }
 if original>free{w.overflow=true}
 return original,nil
}
// Run requires Docker Desktop with Linux containers; it never executes a
// specialist program directly on the Windows host. No network, secrets,
// writable host mounts, privileged mode, or image pulling are permitted.
func Run(ctx context.Context,s Spec,evidenceRoot string)(Receipt,error){
 arguments,err:=BuildDockerArgs(s)
 if err!=nil{return Receipt{},err}
 if evidenceRoot==""||len(evidenceRoot)>1800{return Receipt{},errors.New("private sandbox evidence output required")}
 docker,err:=exec.LookPath("docker")
 if err!=nil{return Receipt{},errors.New("Docker/Linux-container execution unavailable; host execution is forbidden")}
 key,err:=bunnyartifact.ReadKey()
 if err!=nil{return Receipt{},errors.New("OS-owned encryption key required before running specialist")}
 commandContext,cancel:=context.WithTimeout(ctx,time.Duration(s.TimeoutSeconds)*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(commandContext,docker,arguments...)
 // No host environment variables with passwords, provider tokens or proxy
 // settings are supplied to the container. Docker CLI needs only its config.
 cmd.Env=[]string{"PATH="+os.Getenv("PATH"),"HOME="+os.Getenv("HOME")}
 if root:=os.Getenv("USERPROFILE");root!=""{cmd.Env=append(cmd.Env,"USERPROFILE="+root)}
 if sys:=os.Getenv("SYSTEMROOT");sys!=""{cmd.Env=append(cmd.Env,"SYSTEMROOT="+sys)}
 var stdout,stderr cappedWriter
 stdout.limit=64*1024;stderr.limit=16*1024
 cmd.Stdout=&stdout;cmd.Stderr=&stderr
 started:=time.Now()
 err=cmd.Run()
 if commandContext.Err()!=nil{return Receipt{},errors.New("sandbox timed out or was cancelled")}
 if stdout.overflow||stderr.overflow{return Receipt{},errors.New("sandbox output limit exceeded; no success asserted")}
 code:=0
 if err!=nil{
  var exit *exec.ExitError
  if errors.As(err,&exit){code=exit.ExitCode()
  }else{return Receipt{},errors.New("Docker specialist execution failed before starting")}
 }
 content,_:=json.Marshal(struct{
  STDOUT string `json:"stdout"`
  STDERR string `json:"stderr"`
 }{string(stdout.data),string(stderr.data)})
 specRaw,_:=json.Marshal(s)
 receipt:=Receipt{JobID:s.JobID,SpecSHA256:hash(specRaw),ExitCode:code,
  OutputSHA256:hash(content),OutputBytes:len(content),
  DurationMS:time.Since(started).Milliseconds(),Outcome:"isolated_offline_execution",
  Limitation:"Docker isolation is a defense-in-depth boundary, not proof that a third-party image is trustworthy. No model-written source is executed without an operator-selected sandbox profile.",
 }
 if code!=0{receipt.Outcome="sandbox_program_failed"}
 file:=fmt.Sprintf("sandbox-%s-%d",s.JobID,time.Now().UnixNano())
 stored,storeErr:=bunnyartifact.Store(filepath.Join(evidenceRoot,"sandbox"),file,"sandbox_output",content,key)
 if storeErr!=nil{return Receipt{},storeErr}
 receipt.EncryptedOutput=stored
 return receipt,nil
}
