// Package bunnygraph stores bounded, user/agent-supplied asset inventories
// and computes deterministic change sets. It never discovers live assets.
package bunnygraph

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "net/url"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strings"
 "sync"
 "time"
)

const MaxAssets=1024
const MaxLinks=2048
var idRx=regexp.MustCompile("^[A-Za-z0-9_-]{1,64}$")
var shaRx=regexp.MustCompile("^[0-9a-f]{64}$")
var allowedKinds=map[string]bool{"origin":true,"endpoint":true,"service":true,"technology":true,"repository":true,"dependency":true}
var allowedSources=map[string]bool{"captured_http":true,"source_inventory":true,"user_supplied":true,"inferred":true}
var allowedRelations=map[string]bool{"contains":true,"calls":true,"depends_on":true,"protected_by":true,"resolves_to":true}
type Asset struct{
 ID string `json:"id"`
 Kind string `json:"kind"`
 Key string `json:"key"`
 Fingerprint string `json:"fingerprint_sha256"`
 Source string `json:"source"`
}
type Link struct{
 From string `json:"from"`
 To string `json:"to"`
 Relation string `json:"relation"`
}
type Snapshot struct{
 Version int `json:"version"`
 CapturedAt time.Time `json:"captured_at"`
 Assets []Asset `json:"assets"`
 Links []Link `json:"links"`
}
type Diff struct{
 Added []string `json:"added"`
 Removed []string `json:"removed"`
 Changed []string `json:"changed"`
 Unchanged int `json:"unchanged"`
 AddedLinks []string `json:"added_links"`
 RemovedLinks []string `json:"removed_links"`
 FirstSnapshot bool `json:"first_snapshot"`
 Disclaimer string `json:"disclaimer"`
}
type Summary struct{
 CapturedAt time.Time `json:"captured_at"`
 Assets int `json:"assets"`
 Links int `json:"links"`
 ByKind map[string]int `json:"by_kind"`
 BySource map[string]int `json:"by_source"`
}
type Store struct {
 Root string
 Mu sync.Mutex
 Now func()time.Time
}
func New(root string)*Store{return &Store{Root:root,Now:time.Now}}
func (s *Store) now()time.Time{
 if s.Now!=nil{return s.Now().UTC()}
 return time.Now().UTC()
}
func (s *Store) path(session string)(string,error){
 if strings.TrimSpace(session)==""{return "",errors.New("session required")}
 h:=sha256.Sum256([]byte(session))
 return filepath.Join(s.Root,hex.EncodeToString(h[:])+".json"),nil
}
func validKey(s string)bool{
 if strings.TrimSpace(s)==""||len(s)>256||strings.ContainsAny(s,"\r\n\x00"){return false}
 if strings.Contains(s,"://"){
  u,err:=url.Parse(s)
  if err!=nil||u==nil||(u.Scheme!="http"&&u.Scheme!="https")||u.Hostname()==""||
    u.User!=nil||u.RawQuery!=""||u.Fragment!="" {return false}
 }
 return true
}
func Validate(s Snapshot)error{
 if s.Version!=1{return errors.New("unknown snapshot version")}
 if len(s.Assets)>MaxAssets||len(s.Links)>MaxLinks{
  return fmt.Errorf("inventory exceeds %d assets or %d links",MaxAssets,MaxLinks)
 }
 ids:=map[string]bool{}
 for _,a:=range s.Assets{
  if !idRx.MatchString(a.ID)||ids[a.ID]{return fmt.Errorf("invalid/duplicate asset ID %q",a.ID)}
  if !allowedKinds[a.Kind]||!validKey(a.Key)||!shaRx.MatchString(a.Fingerprint)||!allowedSources[a.Source]{
   return fmt.Errorf("asset %q has invalid kind/key/fingerprint/source",a.ID)
  }
  ids[a.ID]=true
 }
 seen:=map[string]bool{}
 for _,edge:=range s.Links{
  if !ids[edge.From]||!ids[edge.To]||!allowedRelations[edge.Relation]{
   return fmt.Errorf("invalid graph edge %q %q %q",edge.From,edge.Relation,edge.To)
  }
  id:=edge.From+"|"+edge.Relation+"|"+edge.To
  if seen[id]{return fmt.Errorf("duplicate graph edge %q",id)}
  seen[id]=true
 }
 return nil
}
func linkKey(l Link)string{return l.From+"|"+l.Relation+"|"+l.To}
func Compare(before,after Snapshot)Diff{
 diff:=Diff{
  Added:[]string{},Removed:[]string{},Changed:[]string{},
  AddedLinks:[]string{},RemovedLinks:[]string{},
  Disclaimer:"All assets and fingerprints were supplied by callers. A graph diff does not prove that network discovery occurred.",
 }
 old:=map[string]Asset{};newAssets:=map[string]Asset{}
 for _,a:=range before.Assets{old[a.ID]=a}
 for _,a:=range after.Assets{
  newAssets[a.ID]=a
  p,ok:=old[a.ID]
  if !ok{diff.Added=append(diff.Added,a.ID)
  }else if p.Key!=a.Key||p.Kind!=a.Kind||p.Fingerprint!=a.Fingerprint||p.Source!=a.Source{
   diff.Changed=append(diff.Changed,a.ID)
  }else{diff.Unchanged++}
 }
 for _,a:=range before.Assets{if _,ok:=newAssets[a.ID];!ok{diff.Removed=append(diff.Removed,a.ID)}}
 oldEdges:=map[string]bool{};newEdges:=map[string]bool{}
 for _,l:=range before.Links{oldEdges[linkKey(l)]=true}
 for _,l:=range after.Links{
  key:=linkKey(l);newEdges[key]=true
  if !oldEdges[key]{diff.AddedLinks=append(diff.AddedLinks,key)}
 }
 for _,l:=range before.Links{
  key:=linkKey(l);if !newEdges[key]{diff.RemovedLinks=append(diff.RemovedLinks,key)}
 }
 sort.Strings(diff.Added);sort.Strings(diff.Removed);sort.Strings(diff.Changed)
 sort.Strings(diff.AddedLinks);sort.Strings(diff.RemovedLinks)
 return diff
}
func (s *Store) load(session string)(Snapshot,error){
 path,err:=s.path(session);if err!=nil{return Snapshot{},err}
 b,err:=os.ReadFile(path);if err!=nil{return Snapshot{},err}
 var snap Snapshot
 if err:=json.Unmarshal(b,&snap);err!=nil{return Snapshot{},fmt.Errorf("inventory corrupt: %w",err)}
 if err:=Validate(snap);err!=nil{return Snapshot{},err}
 return snap,nil
}
func (s *Store) save(session string,snap Snapshot)error{
 path,err:=s.path(session);if err!=nil{return err}
 if err:=os.MkdirAll(s.Root,0700);err!=nil{return err}
 b,err:=json.MarshalIndent(snap,"","  ");if err!=nil{return err}
 f,err:=os.CreateTemp(s.Root,".inventory-*");if err!=nil{return err}
 tmp:=f.Name();defer os.Remove(tmp)
 if err:=f.Chmod(0600);err!=nil{f.Close();return err}
 if _,err:=f.Write(append(b,'\n'));err!=nil{f.Close();return err}
 if err:=f.Sync();err!=nil{f.Close();return err}
 if err:=f.Close();err!=nil{return err}
 return os.Rename(tmp,path)
}
// Update compares a validated new inventory to the previous snapshot and
// atomically persists it. The result does not contain raw asset keys.
func (s *Store) Update(session string,next Snapshot)(Diff,error){
 s.Mu.Lock();defer s.Mu.Unlock()
 next.Version=1
 next.CapturedAt=s.now()
 if err:=Validate(next);err!=nil{return Diff{},err}
 previous,err:=s.load(session)
 first:=os.IsNotExist(err)
 if err!=nil&&!first{return Diff{},err}
 diff:=Compare(previous,next);diff.FirstSnapshot=first
 if err:=s.save(session,next);err!=nil{return Diff{},err}
 return diff,nil
}
func (s *Store) Summary(session string)(Summary,error){
 s.Mu.Lock();defer s.Mu.Unlock()
 snap,err:=s.load(session)
 if err!=nil{return Summary{},err}
 out:=Summary{CapturedAt:snap.CapturedAt,Assets:len(snap.Assets),Links:len(snap.Links),ByKind:map[string]int{},BySource:map[string]int{}}
 for _,a:=range snap.Assets{out.ByKind[a.Kind]++;out.BySource[a.Source]++}
 return out,nil
}
