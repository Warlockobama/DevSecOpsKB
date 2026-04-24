package main

// onboard sub-command: launches the triage-policy onboarding UI.
//
// Two modes (epic #71 slices 1c-iii / 1c-iv):
//
//	zap-kb onboard              — Bubble Tea terminal wizard (default)
//	zap-kb onboard -web         — local HTTP server, auto-opens browser
//	zap-kb onboard -web -port N — same, on a specific port (0 = OS-assigned)
//
// Both modes pre-fill from the existing triage-policy.yaml (or built-in
// defaults) so re-running edits rather than starting blank.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/tui/onboard"
	webonboard "github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/webui/onboard"
)

func runOnboardCommand(args []string) {
	fs := flag.NewFlagSet("onboard", flag.ExitOnError)
	var (
		path string
		web  bool
		port int
	)
	fs.StringVar(&path, "path", "", "Where to write the YAML (default: ./triage-policy.yaml)")
	fs.BoolVar(&web, "web", false, "Launch a browser-based wizard instead of the terminal TUI")
	fs.IntVar(&port, "port", 0, "Port for the web UI (0 = OS-assigned; ignored without -web)")
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

	if web {
		res, werr := webonboard.Run(start, path, port)
		if werr != nil {
			fmt.Fprintf(os.Stderr, "onboard: %v\n", werr)
			os.Exit(1)
		}
		if !res.Saved {
			fmt.Fprintln(os.Stderr, "Onboarding exited without saving.")
			return
		}
		fmt.Printf("Wrote triage policy to %s\n", res.SavedTo)
		return
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
