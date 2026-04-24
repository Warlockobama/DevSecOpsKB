package main

// onboard sub-command: launches the Bubble Tea triage-policy onboarding TUI
// (epic #71 slice 1c-iii). Pre-loads the existing policy (or defaults when
// none) so the user's previous answers are shown as starting values and they
// can walk through again to adjust.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/tui/onboard"
)

func runOnboardCommand(args []string) {
	fs := flag.NewFlagSet("onboard", flag.ExitOnError)
	var path string
	fs.StringVar(&path, "path", "", "Where to write the YAML (default: ./triage-policy.yaml)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "onboard: %v\n", err)
		os.Exit(1)
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "onboard: getwd: %v\n", err)
		os.Exit(1)
	}
	if path == "" {
		path = filepath.Join(cwd, config.PolicyFileName)
	}
	// Start from whatever policy resolves today — either an existing YAML or
	// built-in defaults. The user edits from there rather than starting blank.
	start, src, lerr := config.LoadPolicy(cwd)
	if lerr != nil {
		fmt.Fprintf(os.Stderr, "onboard: load existing policy: %v\n", lerr)
		os.Exit(1)
	}
	if src != "" {
		fmt.Fprintf(os.Stderr, "[info] pre-filling from %s\n", src)
	}
	final, err := onboard.Run(start, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "onboard: %v\n", err)
		os.Exit(1)
	}
	if !final.Saved() {
		fmt.Fprintln(os.Stderr, "Onboarding exited without saving.")
		return
	}
	fmt.Printf("Wrote triage policy to %s\n", final.SavedTo())
}
