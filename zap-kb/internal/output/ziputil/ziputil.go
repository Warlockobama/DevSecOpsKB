package ziputil

import (
    "archive/zip"
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
func Zip(outPath string, inputs ...string) error {
    if len(inputs) == 0 {
        return nil
    }
    if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
        return err
    }
    f, err := os.Create(outPath)
    if err != nil {
        return err
    }
    defer f.Close()
    zw := zip.NewWriter(f)
    defer zw.Close()

    // Determine base dir for relative paths
    base := commonParent(inputs)

    for _, in := range inputs {
        in = filepath.Clean(in)
        info, err := os.Stat(in)
        if err != nil {
            continue
        }
        if info.IsDir() {
            filepath.WalkDir(in, func(path string, d fs.DirEntry, err error) error {
                if err != nil { return nil }
                if d.IsDir() { return nil }
                return addFile(zw, base, path)
            })
        } else {
            if err := addFile(zw, base, in); err != nil {
                return err
            }
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
    if err != nil { return err }
    defer fh.Close()
    w, err := zw.Create(filepath.ToSlash(rel))
    if err != nil { return err }
    _, err = io.Copy(w, fh)
    return err
}

func commonParent(paths []string) string {
    if len(paths) == 0 { return "." }
    segs := strings.Split(filepath.Clean(paths[0]), string(os.PathSeparator))
    for _, p := range paths[1:] {
        parts := strings.Split(filepath.Clean(p), string(os.PathSeparator))
        // shrink segs until they match prefix of parts
        for len(segs) > 0 {
            match := true
            if len(parts) < len(segs) { match = false } else {
                for i := range segs {
                    if segs[i] != parts[i] { match = false; break }
                }
            }
            if match { break }
            segs = segs[:len(segs)-1]
        }
        if len(segs) == 0 { break }
    }
    if len(segs) == 0 { return "." }
    return strings.Join(segs, string(os.PathSeparator))
}

