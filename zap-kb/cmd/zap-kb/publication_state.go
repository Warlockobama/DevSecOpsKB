package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
)

func defaultPublicationStateDir(explicit string, inputs ...string) string {
	if path := strings.TrimSpace(explicit); path != "" {
		return path
	}
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input != "" && input != "-" {
			return filepath.Join(filepath.Dir(input), ".zap-kb-publication-state")
		}
	}
	return ".zap-kb-publication-state"
}

// validateImmutableInputPaths rejects an output that names the same file as a
// producer-owned input. It resolves absolute paths, symlinked parents, and
// existing hard links before any local output or remote publication begins.
func validateImmutableInputPaths(inputs, outputs map[string]string) error {
	for inputName, inputPath := range inputs {
		inputPath = strings.TrimSpace(inputPath)
		if inputPath == "" || inputPath == "-" {
			continue
		}
		for outputName, outputPath := range outputs {
			outputPath = strings.TrimSpace(outputPath)
			if outputPath == "" || outputPath == "-" {
				continue
			}
			same, err := samePath(inputPath, outputPath)
			if err != nil {
				return fmt.Errorf("validate %s and %s paths: %w", inputName, outputName, err)
			}
			if same {
				return fmt.Errorf("%s output aliases immutable %s input", outputName, inputName)
			}
		}
	}
	return nil
}

func samePath(a, b string) (bool, error) {
	ca, err := canonicalPath(a)
	if err != nil {
		return false, err
	}
	cb, err := canonicalPath(b)
	if err != nil {
		return false, err
	}
	if runtime.GOOS == "windows" {
		if strings.EqualFold(ca, cb) {
			return true, nil
		}
	} else if ca == cb {
		return true, nil
	}
	ai, aerr := os.Stat(ca)
	bi, berr := os.Stat(cb)
	if aerr == nil && berr == nil {
		return os.SameFile(ai, bi), nil
	}
	if aerr != nil && !os.IsNotExist(aerr) {
		return false, aerr
	}
	if berr != nil && !os.IsNotExist(berr) {
		return false, berr
	}
	return false, nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if resolvedParent, err := filepath.EvalSymlinks(parent); err == nil {
		return filepath.Join(resolvedParent, filepath.Base(abs)), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	return abs, nil
}

func publicationResultFor(result *publication.Result, destination string) publication.Result {
	var filtered publication.Result
	if result == nil {
		return filtered
	}
	for _, stage := range result.Stages {
		if stage.Destination == destination {
			filtered.Stages = append(filtered.Stages, stage)
		}
	}
	return filtered
}
