package main

// config sub-command: surfaces and seeds the operator-tunable triage policy
// (epic #71 slice 1c-i). Two verbs:
//
//	zap-kb config show           # print the resolved policy + which file (if any) it came from
//	zap-kb config init [-path P] # write a heavily commented default triage-policy.yaml
//
// Policy is loaded from triage-policy.yaml in the cwd, then
// <user-config-home>/devsecopskb/triage-policy.yaml, then built-in defaults.
// Deliberately no -force on init: the YAML is the org's source of truth, so
// overwriting must be a manual `rm` step. CLI flags do NOT mirror policy
// fields — see internal/config/policy.go for the rationale.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

func runConfigCommand(args []string) {
	if len(args) == 0 {
		configUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "show":
		runConfigShow(args[1:])
	case "init":
		runConfigInit(args[1:])
	case "-h", "--help", "help":
		configUsage()
	default:
		fmt.Fprintf(os.Stderr, "config: unknown subcommand %q\n", args[0])
		configUsage()
		os.Exit(2)
	}
}

func configUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  zap-kb config show              Show the resolved triage policy and its source.
  zap-kb config init [-path P]    Write a commented default triage-policy.yaml.
                                  Default path: ./triage-policy.yaml in cwd.`)
}

// runConfigShow prints the merged TriagePolicy plus the absolute path of the
// file it was loaded from (or "(built-in defaults)" if no YAML was found).
// Output is deliberately JSON so callers can pipe it to jq.
func runConfigShow(args []string) {
	fs := flag.NewFlagSet("config show", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "config show: %v\n", err)
		os.Exit(1)
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config show: getwd: %v\n", err)
		os.Exit(1)
	}
	policy, loadedFrom, err := config.LoadPolicy(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config show: %v\n", err)
		os.Exit(1)
	}
	src := loadedFrom
	if src == "" {
		src = "(built-in defaults)"
	}
	out := struct {
		Source string              `json:"source"`
		Policy config.TriagePolicy `json:"policy"`
	}{src, policy}
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "config show: encode: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(enc)
	os.Stdout.WriteString("\n")
}

// runConfigInit writes a commented default policy YAML. Refuses to overwrite
// an existing file — the caller has to delete it first. This is intentional:
// policy is org-level state, not something to clobber by accident.
func runConfigInit(args []string) {
	fs := flag.NewFlagSet("config init", flag.ExitOnError)
	var path string
	fs.StringVar(&path, "path", "", "Where to write the YAML (default: ./triage-policy.yaml)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "config init: %v\n", err)
		os.Exit(1)
	}
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "config init: getwd: %v\n", err)
			os.Exit(1)
		}
		path = filepath.Join(cwd, config.PolicyFileName)
	}
	if err := config.WriteCommentedDefault(path); err != nil {
		fmt.Fprintf(os.Stderr, "config init: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote commented default triage policy to %s\n", path)
	fmt.Println("Edit it to override defaults; partial files are safe (omitted fields keep their defaults).")
}
