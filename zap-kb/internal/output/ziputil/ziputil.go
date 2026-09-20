package ziputil

import (
	"archive/zip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Zip creates a zip archive at outPath, containing the provided input
// files or directories. Directories are added recursively. Paths inside
// the zip are stored relative to the common parent of inputs when
// possible; otherwise, the base name is used.
func Zip(outPath string, inputs ...string) (resultErr error) {
	if len(inputs) == 0 {
		return nil
	}
	target, err := filepath.Abs(outPath)
	if err != nil {
		return err
	}
	var files []string
	seen := map[string]bool{}
	fallbackBase := map[string]string{}
	// Inventory before creating the destination: never recurse into the archive
	// itself, follow symlinks, or admit non-regular files.
	for _, input := range inputs {
		input, err = filepath.Abs(input)
		if err != nil {
			return err
		}
		if strings.EqualFold(input, target) {
			return errors.New("archive output cannot be an input")
		}
		err = filepath.WalkDir(input, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if strings.EqualFold(path, target) {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				return errors.New("archive inputs must not be symlinks")
			}
			if d.IsDir() {
				return nil
			}
			info, e := d.Info()
			if e != nil {
				return e
			}
			if !info.Mode().IsRegular() {
				return errors.New("archive inputs must be regular files")
			}
			if !seen[path] {
				files = append(files, path)
				seen[path] = true
				fallbackBase[path] = filepath.Dir(input)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	f, err := os.Create(target)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	defer func() {
		if e := zw.Close(); resultErr == nil {
			resultErr = e
		}
		if e := f.Close(); resultErr == nil {
			resultErr = e
		}
		if resultErr != nil {
			_ = os.Remove(target)
		}
	}()
	base := commonParent(files)
	for _, path := range files {
		entryBase := base
		if base == "." || base == "" {
			// Different Windows volumes have no common parent. Keep each
			// directory input's hierarchy so relative Markdown links survive.
			entryBase = fallbackBase[path]
		}
		if err := addFile(zw, entryBase, path); err != nil {
			return err
		}
	}
	return nil
}

func addFile(zw *zip.Writer, base, path string) error {
	rel := path
	if strings.HasPrefix(path, base+string(os.PathSeparator)) {
		rel, _ = filepath.Rel(base, path)
	} else {
		rel = filepath.Base(path)
	}
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()
	w, err := zw.Create(filepath.ToSlash(rel))
	if err != nil {
		return err
	}
	_, err = io.Copy(w, fh)
	return err
}

func commonParent(paths []string) string {
	if len(paths) == 0 {
		return "."
	}
	segs := strings.Split(filepath.Clean(paths[0]), string(os.PathSeparator))
	for _, p := range paths[1:] {
		parts := strings.Split(filepath.Clean(p), string(os.PathSeparator))
		// shrink segs until they match prefix of parts
		for len(segs) > 0 {
			match := true
			if len(parts) < len(segs) {
				match = false
			} else {
				for i := range segs {
					if segs[i] != parts[i] {
						match = false
						break
					}
				}
			}
			if match {
				break
			}
			segs = segs[:len(segs)-1]
		}
		if len(segs) == 0 {
			break
		}
	}
	if len(segs) == 0 {
		return "."
	}
	return strings.Join(segs, string(os.PathSeparator))
}
