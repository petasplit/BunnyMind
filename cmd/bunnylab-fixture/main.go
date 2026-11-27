// bunnylab-fixture serves a synthetic response/control pair on loopback.
// It is deliberately not a vulnerable production application.
package main

import (
 "context"
 "flag"
 "fmt"
 "net"
 "net/http"
 "os"
 "os/signal"
 "strconv"
 "syscall"
 "time"
)
const Marker="BUNNYMIND_LAB_MARKER_12345"
func main(){
 port:=flag.Int("port",8765,"local-only port (1..65535)")
 flag.Parse()
 if *port<1||*port>65535{fmt.Fprintln(os.Stderr,"port must be 1..65535");os.Exit(2)}
 listener,err:=net.Listen("tcp",net.JoinHostPort("127.0.0.1",strconv.Itoa(*port)))
 if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 mux:=http.NewServeMux()
 mux.HandleFunc("GET /positive",func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Content-Type","text/plain; charset=utf-8")
  fmt.Fprint(w,"Synthetic response: "+Marker)
 })
 mux.HandleFunc("GET /control",func(w http.ResponseWriter,r *http.Request){
  w.WriteHeader(http.StatusForbidden);fmt.Fprint(w,"No marker for the synthetic control")
 })
 srv:=&http.Server{Handler:mux,ReadHeaderTimeout:5*time.Second}
 done,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
 defer stop()
 go func(){<-done.Done();ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel();_ = srv.Shutdown(ctx)}()
 fmt.Printf("Synthetic fixture available at http://127.0.0.1:%d (Ctrl+C to stop)\n",*port)
 if err=srv.Serve(listener);err!=nil&&err!=http.ErrServerClosed{
  fmt.Fprintln(os.Stderr,err);os.Exit(1)
 }
}
