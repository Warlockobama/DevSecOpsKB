package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runAtlassianCommand(args []string) {
	if len(args) == 0 {
		atlassianUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "check":
		runAtlassianCheck(args[1:])
	case "-h", "--help", "help":
		atlassianUsage()
	default:
		fmt.Fprintf(os.Stderr, "atlassian: unknown subcommand %q\n", args[0])
		atlassianUsage()
		os.Exit(2)
	}
}

func atlassianUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  zap-kb atlassian check    Print redacted Atlassian publish readiness JSON.`)
}

func runAtlassianCheck(args []string) {
	fs := flag.NewFlagSet("atlassian check", flag.ExitOnError)
	var input atlassianConfigInput
	fs.StringVar(&input.ConfluenceURL, "confluence-url", "", "Confluence base URL (env: CONFLUENCE_URL)")
	fs.StringVar(&input.ConfluenceSpace, "confluence-space", "", "Confluence space key (env: CONFLUENCE_SPACE)")
	fs.StringVar(&input.ConfluenceUser, "confluence-user", "", "Confluence username / email (env: CONFLUENCE_USER)")
	fs.StringVar(&input.ConfluenceToken, "confluence-token", "", "Confluence API token (env: CONFLUENCE_TOKEN)")
	fs.StringVar(&input.JiraURL, "jira-url", "", "Jira base URL (env: JIRA_URL)")
	fs.StringVar(&input.JiraProject, "jira-project", "", "Jira project key (env: JIRA_PROJECT)")
	fs.StringVar(&input.JiraUser, "jira-user", "", "Jira username / email (env: JIRA_USER, fallback: CONFLUENCE_USER)")
	fs.StringVar(&input.JiraToken, "jira-token", "", "Jira API token (env: JIRA_API_TOKEN, fallback: CONFLUENCE_TOKEN)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "atlassian check: %v\n", err)
		os.Exit(1)
	}

	out := buildAtlassianCheckOutput(resolveAtlassianConfig(input, os.Getenv))
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "atlassian check: encode: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(data)
	os.Stdout.WriteString("\n")
	if !out.Ready {
		os.Exit(1)
	}
}
