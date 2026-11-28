//go:build windows

package main

import (
    "errors"
    "os"
    "os/exec"
    "strconv"
    "strings"
    "syscall"

    "golang.org/x/sys/windows"
)

// Windows uses a native process handle for identity and lifecycle checks.
// tasklist CSV output is localized, can truncate image names, and does not
// expose a reliable process creation time.
const (
    createNewProcessGroup = 0x00000200
    detachedProcess = 0x00000008
    windowsStillActive = 259
)

func configureDaemonProcess(cmd *exec.Cmd) {
    cmd.SysProcAttr = &syscall.SysProcAttr{
        CreationFlags: createNewProcessGroup | detachedProcess,
    }
}

func openDaemonProcess(pid int) (windows.Handle,error) {
    if pid < 1 { return 0, errors.New("invalid Windows process PID") }
    return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
}

func processAlive(pid int) (bool,error) {
    h,err:=openDaemonProcess(pid)
    if err!=nil { return false,nil }
    defer windows.CloseHandle(h)
    var code uint32
    if err:=windows.GetExitCodeProcess(h,&code);err!=nil {return false,err}
    return code==windowsStillActive,nil
}

func processStartTime(pid int) (string,error) {
    h,err:=openDaemonProcess(pid)
    if err!=nil{return "",err}
    defer windows.CloseHandle(h)
    var created,exited,kernel,user windows.Filetime
    if err:=windows.GetProcessTimes(h,&created,&exited,&kernel,&user);err!=nil{return "",err}
    // Stable 100 ns units since Windows FILETIME epoch. This distinguishes
    // PID reuse, unlike tasklist's executable-name-only placeholder.
    stamp:=(uint64(created.HighDateTime)<<32)|uint64(created.LowDateTime)
    if stamp==0{return "",errors.New("missing Windows process creation time")}
    return strconv.FormatUint(stamp,10),nil
}

func processExecutable(pid int) (string,error) {
    h,err:=openDaemonProcess(pid)
    if err!=nil{return "",err}
    defer windows.CloseHandle(h)
    // Win32 path, not an NT device path; matches os.Executable semantics.
    path:=make([]uint16,32768)
    n:=uint32(len(path))
    if err:=windows.QueryFullProcessImageName(h,0,&path[0],&n);err!=nil{return "",err}
    if n<1||int(n)>len(path){return "",errors.New("empty Windows process image path")}
    return windows.UTF16ToString(path[:n]),nil
}

func processArguments(_ int) ([]string,error) {
    // The daemon starter records the PID and exact executable path; the
    // verifier checks those plus creation time. Cross-process command-line
    // inspection is not needed for managed process identity on Windows.
    return nil,nil
}

func processOwnerUID(_ int) (int,error) {
    // Windows ownership is not represented as a POSIX UID.
    return 0,nil
}

func processesListeningOnPort(port int) ([]int,error) {
    // netstat is only a supplementary port-owner test. Process identity is
    // verified above with native handles, not with netstat's text.
    out,err:=exec.Command("netstat","-ano","-p","TCP").Output()
    if err!=nil{return nil,err}
    want:=":"+strconv.Itoa(port)
    seen:=map[int]bool{}
    var pids []int
    for _,line:=range strings.Split(string(out),"\n"){
        fields:=strings.Fields(line)
        if len(fields)<5||!strings.EqualFold(fields[3],"LISTENING"){continue}
        if !strings.HasSuffix(fields[1],want){continue}
        if pid,e:=strconv.Atoi(fields[4]);e==nil&&!seen[pid]{
            seen[pid]=true
            pids=append(pids,pid)
        }
    }
    return pids,nil
}

func daemonTargetAlive(pid int,_ bool)(bool,error){return processAlive(pid)}
func terminateDaemonProcess(proc *os.Process,_ bool)error{
    // DETACHED_PROCESS has no console to receive Ctrl+C.
    // taskkill /T can fail for a detached process on Windows. Use the
    // native process termination API on the tracked PID instead.
    return proc.Kill()
}
func killDaemonProcess(proc *os.Process,_ bool)error{
    return proc.Kill()
}
