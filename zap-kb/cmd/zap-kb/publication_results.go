package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jira"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// cliExit unwinds deferred cleanup before the single main exit boundary.
type cliExit struct{ code int }

func exitCLI(code int)                  { panic(cliExit{code}) }
func fatalf(format string, args ...any) { log.Printf(format, args...); exitCLI(1) }
func fatal(args ...any)                 { log.Print(args...); exitCLI(1) }
func executeCLI(fn func()) (code int) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(cliExit); ok {
				code = e.code
			} else {
				panic(p)
			}
		}
	}()
	fn()
	return 0
}

// A terminal error is a failure even when an adapter has no item counters.
// Counters describe acknowledged work, never exact committed remote mutations.
func recordPublication(result *publication.Result, destination, stage string, succeeded, skipped, failed int, err error, dry bool, diagnostics ...publication.Diagnostic) {
	if err != nil && failed == 0 {
		failed = 1
	}
	status := publication.Outcome(succeeded, skipped, failed)
	if dry && failed == 0 && err == nil {
		status = publication.Skipped
		succeeded = 0
	}
	if err != nil || (failed > 0 && len(diagnostics) == 0) {
		category, message := "failed", "Stage failed; inspect destination permissions and configuration"
		if err != nil {
			message = synccore.SafeError(err)
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			category = "canceled"
			message = "Stage canceled; an in-flight remote write may have committed without acknowledgment"
		}
		diagnostics = append(diagnostics, publication.Diagnostic{Stage: stage, Category: category, Message: message})
	}
	entry := publication.StageResult{Destination: destination, Stage: stage, Status: status, Required: true, Attempted: succeeded + skipped + failed, Succeeded: succeeded, Skipped: skipped, Failed: failed, Diagnostics: diagnostics}
	result.Stages = append(result.Stages, entry)
	for _, d := range diagnostics {
		log.Printf("%s %s: finding=%s status=%d category=%s retryable=%t: %s", destination, d.Stage, d.FindingID, d.HTTPStatus, d.Category, d.Retryable, d.Message)
		for _, f := range d.Fields {
			log.Printf("%s field=%s category=%s: %s", destination, f.Field, f.Category, f.Message)
		}
	}
}

func publicationSummaryPath(explicit, runOut, out, format, vault string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if strings.TrimSpace(runOut) != "" {
		return runOut + ".publication.json"
	}
	if format != "obsidian" && strings.TrimSpace(out) != "" && out != "-" {
		return out + ".publication.json"
	}
	if strings.TrimSpace(vault) != "" {
		return filepath.Join(vault, "publication.json")
	}
	return "publication.json"
}

func stageRecorded(result *publication.Result, destination, stage string) bool {
	for _, s := range result.Stages {
		if s.Destination == destination && s.Stage == stage {
			return true
		}
	}
	return false
}

func recordUnperformed(result *publication.Result, destination, stage string, prerequisiteFailed bool) {
	if stageRecorded(result, destination, stage) {
		return
	}
	if prerequisiteFailed {
		recordPublication(result, destination, stage, 0, 0, 1, nil, false, publication.Diagnostic{Stage: stage, Category: "prerequisite", Message: "Required stage could not run because its publication prerequisite failed"})
	} else {
		recordPublication(result, destination, stage, 0, 0, 0, nil, true, publication.Diagnostic{Stage: stage, Category: "not_applicable", Message: "No matching remote references or pages, or publication was a dry run"})
	}
}

// File-based field configuration avoids putting sensitive field values in
// process arguments. Reserved identity/evidence/workflow fields stay protected.
func loadJiraCreateFields(path string) (map[string]any, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read Jira create-fields file")
	}
	defer f.Close()
	var fields map[string]any
	d := json.NewDecoder(io.LimitReader(f, 1024*1024))
	d.UseNumber()
	if err := d.Decode(&fields); err != nil || fields == nil {
		return nil, fmt.Errorf("Jira create-fields file must contain a JSON object")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return nil, fmt.Errorf("Jira create-fields file must contain one JSON object")
	}
	return fields, jira.ValidateCreateFields(fields)
}
