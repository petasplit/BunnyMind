// bunny-audit verifies a saved Python proof run without network access.
// This tool authenticates evidence provenance; it does not test or assert impact.
package main

import (
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "os"

    "github.com/enowdev/antares/internal/bunnyartifact"
    "github.com/enowdev/antares/internal/bunnyaudit"
)

func run() error {
    dir := flag.String("run", "", "Directory of a saved BunnyMind Python proof run")
    flag.Parse()
    if *dir == "" || flag.NArg() != 0 {
        return errors.New("usage: bunny-audit --run <private-proof-run-directory>")
    }
    key, err := bunnyartifact.ReadKey()
    if err != nil { return fmt.Errorf("cannot access local evidence key: %w", err) }
    result, err := bunnyaudit.VerifyRun(*dir, key)
    if err != nil { return fmt.Errorf("evidence integrity NOT verified: %w", err) }
    encoded, err := json.MarshalIndent(result, "", "  ")
    if err != nil { return err }
    fmt.Println(string(encoded))
    return nil
}

func main() {
    if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
