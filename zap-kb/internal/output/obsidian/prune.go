package obsidian

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// PruneByScan deletes occurrence markdown files in the vault whose frontmatter
// scan.label equals the provided label. If siteLabel is non-empty, it must also
// match the frontmatter 'domain'. When dryRun is true, no files are removed; the
// returned slice lists the matches.
// Returns the number of files deleted (or that would be deleted) and the list
// of matched file paths (relative to the occurrences dir where possible).
func PruneByScan(root, label, siteLabel string, dryRun bool) (int, []string, error) {
	occDir := filepath.Join(root, "occurrences")

	info, err := os.Stat(occDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	if !info.IsDir() {
		return 0, nil, nil
	}

	label = strings.TrimSpace(label)
	siteLabel = strings.TrimSpace(siteLabel)
	if label == "" {
		return 0, nil, nil
	}

	var absMatches []string
	var relMatches []string

	walkErr := filepath.WalkDir(occDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}

		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		fm := extractFrontmatter(string(b))
		if strings.TrimSpace(fm["scan.label"]) != label {
			return nil
		}
		if siteLabel != "" {
			dom := strings.TrimSpace(fm["domain"])
			if dom != siteLabel {
				return nil
			}
		}

		absMatches = append(absMatches, path)
		rel := path
		if r, err := filepath.Rel(occDir, path); err == nil {
			rel = filepath.ToSlash(r)
		} else {
			rel = filepath.ToSlash(path)
		}
		relMatches = append(relMatches, rel)
		return nil
	})
	if walkErr != nil {
		return 0, nil, walkErr
	}

	if dryRun {
		return len(relMatches), relMatches, nil
	}

	deleted := 0
	var removeErr error
	for _, abs := range absMatches {
		if err := os.Remove(abs); err != nil {
			if removeErr == nil {
				removeErr = err
			}
			continue
		}
		deleted++
	}

	return deleted, relMatches, removeErr
}
