package bunnybench

import (
 "testing"
)
func study() Study {
 return Study{Manifest:Manifest{Benchmark:"training-lab-v1",Cases:[]Case{{ID:"SQLI"},{ID:"IDOR"},{ID:"AUTH_BYPASS"},{ID:"TRAVERSAL"}}},
 Trials:[]Trial{{RunID:"r1",Model:"local-model",ProofEvents:[]string{"SQLI","IDOR"},PassedControls:[]string{"SQLI","IDOR"},Reported:[]string{"SQLI","IDOR","TRAVERSAL","UNKNOWN"}}}}
}
func TestPrecisionRecallStrict(t *testing.T){
 r,e:=ScoreStudy(study());if e!=nil{t.Fatal(e)}
 s:=r.Trials[0]
 if s.SupportedCount!=2||s.ReportedCount!=4||s.Precision!=0.5||s.Recall!=0.5||s.ProofCoverage!=2{t.Fatalf("%+v",s)}
}
func TestNoControlNoSupport(t *testing.T){
 x:=study();x.Trials[0].PassedControls=nil
 r,e:=ScoreStudy(x);if e!=nil{t.Fatal(e)}
 if r.Trials[0].SupportedCount!=0||r.Trials[0].Precision!=0{t.Fatal("control-free claim counted")}
}
func TestProofNotReportedIsMiss(t *testing.T){
 x:=study();x.Trials[0].Reported=[]string{}
 r,e:=ScoreStudy(x);if e!=nil{t.Fatal(e)}
 if r.Trials[0].Recall!=0||r.Trials[0].MissedCount!=4{t.Fatal("unreported proof incorrectly credited")}
}
func TestDuplicateClaimsCannotInflate(t *testing.T){
 x:=study();x.Trials[0].Reported=[]string{"SQLI","SQLI"};x.Trials[0].ProofEvents=[]string{"SQLI","SQLI"}
 r,e:=ScoreStudy(x);if e!=nil{t.Fatal(e)}
 if r.Trials[0].ReportedCount!=1||r.Trials[0].SupportedCount!=1{t.Fatal("duplicate inflated score")}
}
func TestUnknownProofEventRejected(t *testing.T){
 x:=study();x.Trials[0].ProofEvents=[]string{"SOME_UNKNOWN_CASE"}
 if _,e:=ScoreStudy(x);e==nil{t.Fatal("unknown proof accepted")}
}
func TestDuplicateGroundTruthRejected(t *testing.T){
 x:=study();x.Manifest.Cases=append(x.Manifest.Cases,Case{ID:"SQLI"})
 if _,e:=ScoreStudy(x);e==nil{t.Fatal("duplicate ground truth accepted")}
}
func TestDuplicateRunRejected(t *testing.T){
 x:=study();x.Trials=append(x.Trials,x.Trials[0])
 if _,e:=ScoreStudy(x);e==nil{t.Fatal("duplicate run accepted")}
}
func TestTwoModelAverages(t *testing.T){
 x:=study();x.Trials=append(x.Trials,Trial{RunID:"r2",Model:"cloud-model",
 ProofEvents:[]string{"SQLI","IDOR","AUTH_BYPASS","TRAVERSAL"},
 PassedControls:[]string{"SQLI","IDOR","AUTH_BYPASS","TRAVERSAL"},
 Reported:[]string{"SQLI","IDOR","AUTH_BYPASS","TRAVERSAL"}})
 r,e:=ScoreStudy(x);if e!=nil{t.Fatal(e)}
 if len(r.Models)!=2||r.Models[0].Model!="cloud-model"||r.Models[0].MeanRecall!=1{t.Fatalf("%+v",r.Models)}
}
func TestMissingCaseRejected(t *testing.T){
 x:=study();x.Manifest.Cases=nil
 if _,e:=ScoreStudy(x);e==nil{t.Fatal("missing truth accepted")}
}
