package jsondump

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WritePretty serialises v as indented JSON and writes it to path atomically.
// It writes to a temp file in the same directory first, then renames — so a
// crash mid-write cannot leave a partially-written (corrupted) file.
// File mode is 0o600 (owner read/write only) to protect triage records.
func WritePretty(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".kb-*.tmp")
	if err != nil {
		return fmt.Errorf("jsondump: create temp: %w", err)
	}
	tmpName := tmp.Name()

	// Always clean up the temp file on failure.
	success := false
	defer func() {
		if !success {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("jsondump: encode: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("jsondump: chmod: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("jsondump: close temp: %w", err)
	}

	// Atomic rename — on POSIX this is guaranteed atomic; on Windows NTFS it is
	// effectively atomic (os.Rename uses MoveFileEx with REPLACE_EXISTING).
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("jsondump: rename: %w", err)
	}
	success = true
	return nil
}
