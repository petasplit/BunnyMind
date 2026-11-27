package bunnyaudit

import (
    "bytes"
    "crypto/rand"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/enowdev/antares/internal/bunnyartifact"
)

func fixture(t *testing.T) (string, []byte) {
    t.Helper()
    dir := filepath.Join(t.TempDir(), "audit-test")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil { t.Fatal(err) }
    script := []byte("print('approved synthetic evidence')\n")
    planBytes := []byte(`{"engagement_id":"lab","run_id":"audit-test","cases":[]}`)
    secret := []byte(`{"fixture":"private owner account session=not-for-logs","observations":[]}`)
    v := validation{EngagementID:"lab", RunID:"audit-test",
        ScriptSHA256:digest(script), PlanSHA256:digest(planBytes),
        RawEvidenceFile:"transcript.enc", RawEvidenceSHA256:digest(secret)}
    rawV, err := json.Marshal(v)
    if err != nil { t.Fatal(err) }
    for name, contents := range map[string][]byte{
        "scenario.py":script, "plan.json":planBytes, "validation.json":rawV,
        "report.md":[]byte("# synthetic unverified proof\n"),
        "README.txt":[]byte("Private evidence belongs in the vault.\n"),
    } {
        if err := os.WriteFile(filepath.Join(dir, name), contents, 0600); err != nil { t.Fatal(err) }
    }
    if _, err := bunnyartifact.Store(dir,"transcript","http_proof",secret,key); err != nil { t.Fatal(err) }
    return dir,key
}

func TestSealedRunVerifiesWithoutLeakingTranscript(t *testing.T) {
    dir,key := fixture(t)
    manifest,err := SealRun(dir,key)
    if err != nil { t.Fatal(err) }
    if manifest.Version != 1 || len(manifest.Files) != 6 || manifest.MAC == "" {
        t.Fatalf("incomplete evidence seal: %+v", manifest)
    }
    raw,err := os.ReadFile(filepath.Join(dir,sealFile))
    if err != nil { t.Fatal(err) }
    if bytes.Contains(raw, []byte("session=not-for-logs")) {
        t.Fatal("seal contains private unencrypted HTTP evidence")
    }
    result,err := VerifyRun(dir,key)
    if err != nil { t.Fatal(err) }
    if result.Result != "integrity_verified_impact_unassessed" || result.FilesVerified != 6 {
        t.Fatalf("incorrect audit conclusion: %+v", result)
    }
    if _,err := SealRun(dir,key); err == nil { t.Fatal("seal was overwritten") }
}

func TestTamperingAndWrongKeysFailClosed(t *testing.T) {
    names := []string{"scenario.py","plan.json","validation.json","report.md","README.txt","transcript.enc","seal.json"}
    for _,name := range names {
        t.Run(name,func(t *testing.T) {
            dir,key := fixture(t)
            if _,err := SealRun(dir,key); err != nil { t.Fatal(err) }
            p := filepath.Join(dir,name)
            file,err := os.OpenFile(p,os.O_APPEND|os.O_WRONLY,0600)
            if err != nil { t.Fatal(err) }
            if _,err = file.WriteString("tampered"); err != nil { t.Fatal(err) }
            _ = file.Close()
            if _,err := VerifyRun(dir,key); err == nil {
                t.Fatalf("modified %s passed integrity verification", name)
            }
        })
    }
    dir,key := fixture(t)
    if _,err := SealRun(dir,key); err != nil { t.Fatal(err) }
    other := bytes.Repeat([]byte{0xcc},32)
    if _,err := VerifyRun(dir,other); err == nil { t.Fatal("wrong key verified capture") }
    if _,err := VerifyRun(dir,key); err != nil { t.Fatal(err) }
}

func TestRejectSymlinkAndUnsealedCapture(t *testing.T) {
    dir,key := fixture(t)
    if _,err := VerifyRun(dir,key); err == nil {
        t.Fatal("capture with no authenticated seal was accepted")
    }
    p := filepath.Join(dir,"report.md")
    if err := os.Remove(p); err != nil { t.Fatal(err) }
    if err := os.Symlink(filepath.Join(dir,"README.txt"),p); err != nil {
        if strings.Contains(strings.ToLower(err.Error()),"privilege") { t.Skip("symlink privilege unavailable") }
        t.Fatal(err)
    }
    if _,err := SealRun(dir,key); err == nil { t.Fatal("symlink in evidence bundle accepted") }
}
