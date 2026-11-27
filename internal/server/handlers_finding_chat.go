package server

import (
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "strings"

 "github.com/enowdev/antares/internal/findings"
)

// handleFindingChat provides a persistent, per-session and per-finding
// conversation grounded in the existing finding ledger. It never makes a
// model call or executes a security probe; answers are transparent rules.
func (s *Server) handleFindingChat(w http.ResponseWriter,r *http.Request){
 session:=strings.TrimSpace(r.URL.Query().Get("session"))
 id:=strings.TrimSpace(r.URL.Query().Get("finding"))
 if session==""||id==""||len(session)>160||s.agent==nil||s.agent.Findings()==nil||s.findingChats==nil{
  writeError(w,http.StatusBadRequest,errors.New("valid engagement and finding required"));return
 }
 list,err:=s.agent.Findings().List(session)
 if err!=nil{writeError(w,http.StatusInternalServerError,errors.New("finding ledger unavailable"));return}
 var record *findings.Finding
 for i:=range list{if list[i].ID==id{record=&list[i];break}}
 if record==nil{writeError(w,http.StatusNotFound,errors.New("finding not present in this engagement"));return}
 var turns any
 switch r.Method{
 case http.MethodGet:
  turns,err=s.findingChats.Load(session,id)
 case http.MethodPost:
  var body struct{Question string `json:"question"`}
  decoder:=json.NewDecoder(io.LimitReader(r.Body,2048))
  decoder.DisallowUnknownFields()
  if e:=decoder.Decode(&body);e!=nil{
   writeError(w,http.StatusBadRequest,errors.New("invalid finding question"));return
  }
  var trailing any
  if decoder.Decode(&trailing)!=io.EOF{
   writeError(w,http.StatusBadRequest,errors.New("finding question must contain one JSON object"));return
  }
  turns,err=s.findingChats.Append(session,id,body.Question,*record)
 default:
  writeError(w,http.StatusMethodNotAllowed,errors.New("unsupported finding chat method"));return
 }
 if err!=nil{
  writeError(w,http.StatusBadRequest,errors.New("finding discussion unavailable or invalid"));return
 }
 writeJSON(w,http.StatusOK,map[string]any{
  "session":session,"finding_id":id,
  "title":record.Title,"severity":record.Severity,"status":record.Status,
  "turns":turns,
  "note":"Grounded finding review only. Answers are deterministic and do not independently verify the underlying finding.",
 })
}
