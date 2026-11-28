package bunnyprogram

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"

 "github.com/enowdev/antares/internal/bunnyguard"
)

type Proposal struct {
 ProgramURL string `json:"program_url"`
 PageSHA256 string `json:"page_sha256"`
 ReviewRequired bool `json:"review_required"`
 ApprovedForActiveTesting bool `json:"approved_for_active_testing"`
 ProposedGuard bunnyguard.Policy `json:"proposed_guard"`
 Caution string `json:"caution"`
}
func Draft(snapshot Snapshot)(Proposal,error){
 if snapshot.PageSHA256==""||snapshot.ProgramURL==""{return Proposal{},errors.New("verified program snapshot required")}
 exact:=snapshot.ProposedExactWebOrigins
 if len(exact)==0{return Proposal{},errors.New("program has no verified finite first-party web origins")}
 nameHash:=sha256.Sum256([]byte(snapshot.ProgramURL))
 p:=bunnyguard.Policy{
  EngagementID:"ywh_"+hex.EncodeToString(nameHash[:8]),
  AllowedOrigins:exact,
  AllowedMethods:[]string{"GET","HEAD"},
  MaxNetworkCalls:40,
  MinIntervalMS:500,
 }
 for _,note:=range snapshot.Notes{
  if strings.Contains(note,"BugBounty/42 (YWH)"){p.UserAgent="BugBounty/42 (YWH)";break}
 }
 return Proposal{ProgramURL:snapshot.ProgramURL,PageSHA256:snapshot.PageSHA256,
  ReviewRequired:true,ApprovedForActiveTesting:false,ProposedGuard:p,
  Caution:"Draft only. Review exclusions, dynamic wildcard scopes, consent and impact restrictions. Operator must explicitly activate a narrowed BunnyGuard manifest; this file is not an authorization token."},nil
}
// SaveProposal saves a source-bound JSON proposal without touching the
// BunnyGuard environment variable or enabling any active network calls.
func SaveProposal(root string,p Proposal)(string,error){
 if root==""||len(root)>2000||!p.ReviewRequired||p.ApprovedForActiveTesting{
  return "",errors.New("invalid inactive program proposal destination")
 }
 if len(p.PageSHA256)<16{return "",errors.New("missing source hash")}
 folder:=filepath.Join(root,p.ProposedGuard.EngagementID)
 if err:=os.MkdirAll(folder,0700);err!=nil{return "",err}
 filename:="scope-proposal-"+p.PageSHA256[:16]+".json"
 full:=filepath.Join(folder,filename)
 raw,err:=json.MarshalIndent(p,"","  ")
 if err!=nil{return "",err}
 fd,err:=os.OpenFile(full,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if os.IsExist(err){return full,nil}
 if err!=nil{return "",err}
 if _,err:=fd.Write(raw);err!=nil{fd.Close();os.Remove(full);return "",err}
 if err:=fd.Close();err!=nil{return "",err}
 return full,nil
}
