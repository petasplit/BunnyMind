package server

import (
 "errors"
 "net/http"
 "strings"

 "github.com/enowdev/antares/internal/bunnysarif"
)
func (s *Server) handleEngagementSARIF(w http.ResponseWriter,r *http.Request){
 session:=strings.TrimSpace(r.URL.Query().Get("session"))
 if session==""||len(session)>160||s.agent==nil||s.agent.Findings()==nil{
  writeError(w,http.StatusBadRequest,errors.New("engagement session required"));return
 }
 list,err:=s.agent.Findings().List(session)
 if err!=nil{writeError(w,http.StatusInternalServerError,errors.New("finding ledger unavailable"));return}
 data,err:=bunnysarif.Build(list)
 if err!=nil{writeError(w,http.StatusInternalServerError,errors.New("SARIF export failed"));return}
 w.Header().Set("Content-Type","application/sarif+json; charset=utf-8")
 w.Header().Set("Content-Disposition","attachment; filename=\"bunnymind-findings.sarif\"")
 w.Header().Set("Cache-Control","no-store")
 w.WriteHeader(http.StatusOK)
 _,_=w.Write(data)
}
