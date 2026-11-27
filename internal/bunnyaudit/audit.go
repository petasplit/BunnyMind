// Package bunnyaudit provides offline, key-authenticated integrity checks for
// BunnyMind Python proof captures. Integrity is not exploit verification.
package bunnyaudit

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"

    "github.com/enowdev/antares/internal/bunnyartifact"
)

const sealFile = "seal.json"

var requiredFiles = []string{
    "scenario.py", "plan.json", "validation.json",
    "report.md", "README.txt", "transcript.enc",
}

type FileDigest struct {
    Name string `json:"name"`
    Bytes int64 `json:"bytes"`
    SHA256 string `json:"sha256"`
}

type Manifest struct {
    Version int `json:"version"`
    EngagementID string `json:"engagement_id"`
    RunID string `json:"run_id"`
    CapturedEvidenceSHA256 string `json:"captured_evidence_sha256"`
    SealedAt string `json:"sealed_at"`
    Files []FileDigest `json:"files"`
    MAC string `json:"mac"`
}

type Verification struct {
    EngagementID string `json:"engagement_id"`
    RunID string `json:"run_id"`
    FilesVerified int `json:"files_verified"`
    Result string `json:"result"`
    Limitation string `json:"limitation"`
}

type validation struct {
    EngagementID string `json:"engagement_id"`
    RunID string `json:"run_id"`
    ScriptSHA256 string `json:"script_sha256"`
    PlanSHA256 string `json:"plan_sha256"`
    RawEvidenceFile string `json:"raw_evidence_file"`
    RawEvidenceSHA256 string `json:"raw_evidence_sha256"`
}

type plan struct {
    EngagementID string `json:"engagement_id"`
    RunID string `json:"run_id"`
}

func digest(data []byte) string {
    h := sha256.Sum256(data)
    return hex.EncodeToString(h[:])
}

func readRegular(dir, name string) ([]byte, error) {
    path := filepath.Join(dir, name)
    info, err := os.Lstat(path)
    if err != nil { return nil, err }
    if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 9*1024*1024 {
        return nil, fmt.Errorf("%s must be a nonempty regular file under 9 MiB", name)
    }
    return os.ReadFile(path)
}

func loadValidation(dir string) (validation, error) {
    raw, err := readRegular(dir, "validation.json")
    if err != nil { return validation{}, err }
    var v validation
    decoder := json.NewDecoder(bytes.NewReader(raw))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&v); err != nil { return validation{}, err }
    var leftover any
    if decoder.Decode(&leftover) != io.EOF { return validation{}, errors.New("trailing validation data") }
    if v.RunID == "" || v.EngagementID == "" || v.RawEvidenceFile != "transcript.enc" ||
        v.ScriptSHA256 == "" || v.PlanSHA256 == "" || v.RawEvidenceSHA256 == "" {
        return validation{}, errors.New("incomplete proof validation metadata")
    }
    return v, nil
}

func checkContents(dir string, v validation, key []byte) error {
    src, err := readRegular(dir, "scenario.py")
    if err != nil { return err }
    if digest(src) != v.ScriptSHA256 { return errors.New("generated Python source hash differs from validation") }
    rawPlan, err := readRegular(dir, "plan.json")
    if err != nil { return err }
    if digest(rawPlan) != v.PlanSHA256 { return errors.New("proof plan hash differs from validation") }
    var p plan
    if err := json.Unmarshal(rawPlan, &p); err != nil { return err }
    if p.EngagementID != v.EngagementID || p.RunID != v.RunID || filepath.Base(filepath.Clean(dir)) != v.RunID {
        return errors.New("run identity differs across plan, validation and evidence directory")
    }
    raw, err := bunnyartifact.Open(dir, "transcript", "http_proof", key)
    if err != nil { return fmt.Errorf("encrypted HTTP transcript authentication failed: %w", err) }
    if digest(raw) != v.RawEvidenceSHA256 { return errors.New("decrypted HTTP transcript hash differs from validation") }
    return nil
}

func macFor(m Manifest, key []byte) (string, error) {
    if len(key) != 32 { return "", errors.New("32-byte local evidence key required") }
    m.MAC = ""
    payload, err := json.Marshal(m)
    if err != nil { return "", err }
    derivation := hmac.New(sha256.New, key)
    _, _ = derivation.Write([]byte("BunnyMind evidence audit MAC v1"))
    auth := hmac.New(sha256.New, derivation.Sum(nil))
    _, _ = auth.Write(payload)
    return hex.EncodeToString(auth.Sum(nil)), nil
}

// SealRun records hashes of the complete saved run and authenticates the
// manifest with a domain-separated HMAC derived from the local vault key.
// Existing seals are never overwritten.
func SealRun(dir string, key []byte) (Manifest, error) {
    if len(key) != 32 { return Manifest{}, errors.New("32-byte evidence key required") }
    v, err := loadValidation(dir)
    if err != nil { return Manifest{}, err }
    if err := checkContents(dir, v, key); err != nil { return Manifest{}, err }
    m := Manifest{Version:1, EngagementID:v.EngagementID, RunID:v.RunID,
        CapturedEvidenceSHA256:v.RawEvidenceSHA256,
        SealedAt:time.Now().UTC().Format(time.RFC3339Nano),
        Files:make([]FileDigest, 0, len(requiredFiles))}
    for _, name := range requiredFiles {
        contents, err := readRegular(dir, name)
        if err != nil { return Manifest{}, err }
        m.Files = append(m.Files, FileDigest{Name:name, Bytes:int64(len(contents)), SHA256:digest(contents)})
    }
    m.MAC, err = macFor(m, key)
    if err != nil { return Manifest{}, err }
    encoded, err := json.MarshalIndent(m, "", "  ")
    if err != nil { return Manifest{}, err }
    fd, err := os.OpenFile(filepath.Join(dir, sealFile), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
    if err != nil { return Manifest{}, fmt.Errorf("evidence seal already present or inaccessible: %w", err) }
    if _, err = fd.Write(encoded); err != nil { _ = fd.Close(); _ = os.Remove(filepath.Join(dir, sealFile)); return Manifest{}, err }
    if err = fd.Sync(); err != nil { _ = fd.Close(); return Manifest{}, err }
    if err = fd.Close(); err != nil { return Manifest{}, err }
    return m, nil
}

// VerifyRun detects changes to scripts, plans, redacted reports, and encrypted
// captures. Only file integrity and provenance are asserted, never impact.
func VerifyRun(dir string, key []byte) (Verification, error) {
    if len(key) != 32 { return Verification{}, errors.New("32-byte evidence key required") }
    raw, err := readRegular(dir, sealFile)
    if err != nil { return Verification{}, err }
    if len(raw) > 16000 { return Verification{}, errors.New("oversized evidence seal") }
    var m Manifest
    decoder := json.NewDecoder(bytes.NewReader(raw))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&m); err != nil { return Verification{}, err }
    var extra any
    if decoder.Decode(&extra) != io.EOF { return Verification{}, errors.New("trailing evidence seal data") }
    if m.Version != 1 || m.RunID == "" || m.EngagementID == "" ||
        len(m.Files) != len(requiredFiles) || m.CapturedEvidenceSHA256 == "" {
        return Verification{}, errors.New("invalid evidence seal structure")
    }
    if _, err := time.Parse(time.RFC3339Nano, m.SealedAt); err != nil { return Verification{}, errors.New("invalid seal timestamp") }
    expected, err := macFor(m, key)
    if err != nil { return Verification{}, err }
    gotBytes, err := hex.DecodeString(m.MAC)
    if err != nil { return Verification{}, errors.New("invalid evidence seal MAC") }
    expectedBytes, _ := hex.DecodeString(expected)
    if !hmac.Equal(gotBytes, expectedBytes) {
        return Verification{}, errors.New("evidence seal authentication failed")
    }
    for i, name := range requiredFiles {
        entry := m.Files[i]
        if entry.Name != name { return Verification{}, errors.New("evidence seal file list differs from required files") }
        contents, err := readRegular(dir, name)
        if err != nil { return Verification{}, err }
        if int64(len(contents)) != entry.Bytes || digest(contents) != entry.SHA256 {
            return Verification{}, fmt.Errorf("sealed file integrity failed: %s", name)
        }
    }
    v, err := loadValidation(dir)
    if err != nil { return Verification{}, err }
    if m.RunID != v.RunID || m.EngagementID != v.EngagementID ||
        m.CapturedEvidenceSHA256 != v.RawEvidenceSHA256 {
        return Verification{}, errors.New("run identity or evidence digest differs from authenticated manifest")
    }
    if err := checkContents(dir, v, key); err != nil { return Verification{}, err }
    return Verification{EngagementID:m.EngagementID, RunID:m.RunID,
        FilesVerified:len(requiredFiles), Result:"integrity_verified_impact_unassessed",
        Limitation:"Local HMAC and encrypted-capture verification detect modification after sealing; they do not establish exploitability, legal authorization or independent impact."}, nil
}
