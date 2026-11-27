package bunnytimeline

import (
	"os"
	"strings"
	"sync"
	"testing"
)

const testDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAppendReplayAndBranch(t *testing.T) {
	s:=New(t.TempDir())
	first,err:=s.Append("scan-A",Entry{Lane:"activity",Action:"inspect",State:"succeeded",Source:SourceAgent,TaskID:"recon"})
	if err!=nil{t.Fatal(err)}
	if first.Seq!=1||first.PrevSHA256!=genesis||first.SHA256==""{t.Fatalf("bad first event: %+v",first)}
	second,err:=s.Append("scan-A",Entry{Lane:"exploration",Action:"verify",State:"succeeded",Source:SourceAgent,ParentSeq:1,EvidenceSHA256:testDigest})
	if err!=nil{t.Fatal(err)}
	if second.Seq!=2||second.PrevSHA256!=first.SHA256{t.Fatalf("broken linkage: %+v",second)}
	p,err:=s.Read("scan-A","",0,100)
	if err!=nil{t.Fatal(err)}
	if !p.Summary.IntegrityOK||p.Summary.Total!=2||p.Summary.ByLane["activity"]!=1||p.Summary.ByLane["exploration"]!=1{t.Fatalf("bad summary: %+v",p.Summary)}
	if len(p.Events)!=2||p.Events[1].ParentSeq!=1{t.Fatalf("bad replay: %+v",p.Events)}
	next,err:=s.Read("scan-A","exploration",1,1)
	if err!=nil||len(next.Events)!=1||next.Events[0].Seq!=2{t.Fatalf("bad page: %+v %v",next,err)}
	empty,err:=New(s.Root).Read("scan-B","",0,100)
	if err!=nil||empty.Summary.Total!=0{t.Fatalf("cross-session leak: %+v %v",empty,err)}
}

func TestTamperDetectionPreventsFurtherAppend(t *testing.T) {
	s:=New(t.TempDir())
	_,err:=s.Append("scan",Entry{Lane:"activity",Action:"inspect",State:"succeeded",Source:SourceAgent})
	if err!=nil{t.Fatal(err)}
	p,err:=s.path("scan");if err!=nil{t.Fatal(err)}
	raw,err:=os.ReadFile(p);if err!=nil{t.Fatal(err)}
	changed:=strings.Replace(string(raw),`"succeeded"`,`"failed"`,1)
	if changed==string(raw){t.Fatal("could not produce tampered record")}
	if err:=os.WriteFile(p,[]byte(changed),0600);err!=nil{t.Fatal(err)}
	if _,err:=New(s.Root).Read("scan","",0,10);err==nil{t.Fatal("tamper was not detected")}
	if _,err:=s.Append("scan",Entry{Lane:"activity",Action:"report",State:"queued",Source:SourceAgent});err==nil{t.Fatal("append accepted corrupted file")}
}

func TestRejectsUnsafeAndFabricatedTraffic(t *testing.T) {
	s:=New(t.TempDir())
	bad:=[]Entry{
		{Lane:"activity",Action:"inspect",State:"succeeded",Source:SourceAgent,AssetID:"https://secret.example/?token=123"},
		{Lane:"auth",Action:"sign_in",State:"succeeded",Source:SourceAgent,TaskID:"Bearer token"},
		{Lane:"traffic",Action:"request",State:"succeeded",Source:SourceAgent,HTTPMethod:"GET",HTTPStatus:200,EvidenceSHA256:testDigest,Origin:"https://example.test"},
		{Lane:"traffic",Action:"request",State:"succeeded",Source:SourceTool,HTTPMethod:"POST",HTTPStatus:200,EvidenceSHA256:testDigest,Origin:"https://example.test"},
		{Lane:"traffic",Action:"request",State:"succeeded",Source:SourceTool,HTTPMethod:"GET",HTTPStatus:200,EvidenceSHA256:testDigest,Origin:"https://example.test/path"},
		{Lane:"exploration",Action:"verify",State:"succeeded",Source:SourceAgent},
		{Lane:"exploration",Action:"inspect",State:"queued",Source:SourceAgent,ParentSeq:42},
	}
	for i,e:=range bad{if _,err:=s.Append("scan",e);err==nil{t.Fatalf("unsafe entry %d accepted: %+v",i,e)}}
	p,err:=s.Read("scan","",0,10);if err!=nil||p.Summary.Total!=0{t.Fatalf("rejected data was persisted: %+v %v",p,err)}
}

func TestScopedReadMetadataReplaysWithoutBodies(t *testing.T) {
	s:=New(t.TempDir())
	in:=Entry{Lane:"traffic",Action:"request",State:"succeeded",Source:SourceTool,
		HTTPMethod:"GET",HTTPStatus:200,Bytes:128,Origin:"https://example.test",
		AssetID:"urlsha_1",EvidenceSHA256:testDigest}
	if _,err:=s.Append("scan",in);err!=nil{t.Fatal(err)}
	page,err:=New(s.Root).Read("scan","traffic",0,10)
	if err!=nil||page.Summary.ByLane["traffic"]!=1{t.Fatalf("metadata not replayed: %v %+v",err,page)}
	raw,err:=os.ReadFile(mustPath(t,s,"scan"));if err!=nil{t.Fatal(err)}
	if strings.Contains(string(raw),"Authorization")||strings.Contains(string(raw),"Cookie")||strings.Contains(string(raw),"/path?"){t.Fatal("raw traffic leaked")}
}
func mustPath(t *testing.T,s *Store,session string) string {
	t.Helper();p,err:=s.path(session);if err!=nil{t.Fatal(err)};return p
}

func TestConcurrentAppendSingleProcess(t *testing.T) {
	s:=New(t.TempDir())
	var wg sync.WaitGroup
	errs:=make(chan error,24)
	for i:=0;i<24;i++{
		wg.Add(1)
		go func(){
			defer wg.Done()
			_,err:=s.Append("scan",Entry{Lane:"activity",Action:"inspect",State:"succeeded",Source:SourceAgent})
			errs<-err
		}()
	}
	wg.Wait();close(errs)
	for err:=range errs{if err!=nil{t.Fatal(err)}}
	p,err:=New(s.Root).Read("scan","",0,100)
	if err!=nil||p.Summary.Total!=24{t.Fatalf("lost timeline events: %+v %v",p.Summary,err)}
}
