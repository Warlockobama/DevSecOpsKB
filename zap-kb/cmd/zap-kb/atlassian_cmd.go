package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jira"
)

func runAtlassianCommand(args []string) {
	if len(args) == 0 {
		atlassianUsage()
		exitCLI(2)
	}
	switch args[0] {
	case "check":
		runAtlassianCheck(args[1:])
	case "-h", "--help", "help":
		atlassianUsage()
	default:
		fmt.Fprintf(os.Stderr, "atlassian: unknown subcommand %q\n", args[0])
		atlassianUsage()
		exitCLI(2)
	}
}

func atlassianUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  zap-kb atlassian check    Print redacted Atlassian publish readiness JSON.`)
}

func runAtlassianCheck(args []string) {
	fs := flag.NewFlagSet("atlassian check", flag.ContinueOnError)
	var input atlassianConfigInput
	var remote bool
	var issueType, component, createFieldsFile string
	fs.BoolVar(&remote, "remote", false, "Also run bounded read-only Jira project permissions/create metadata checks; never creates an issue")
	fs.StringVar(&issueType, "jira-issue-type", "Bug", "Jira issue type name or numeric ID")
	fs.StringVar(&component, "jira-component", "", "Jira component name")
	fs.StringVar(&createFieldsFile, "jira-create-fields-file", "", "JSON file of configured create fields (env: JIRA_CREATE_FIELDS_FILE)")
	fs.StringVar(&input.ConfluenceURL, "confluence-url", "", "Confluence base URL (env: CONFLUENCE_URL)")
	fs.StringVar(&input.ConfluenceSpace, "confluence-space", "", "Confluence space key (env: CONFLUENCE_SPACE)")
	fs.StringVar(&input.ConfluenceUser, "confluence-user", "", "Confluence username / email (env: CONFLUENCE_USER)")
	fs.StringVar(&input.ConfluenceToken, "confluence-token", "", "Confluence API token (env: CONFLUENCE_TOKEN)")
	fs.StringVar(&input.ConfluenceDeployment, "confluence-deployment", "", "Confluence deployment: auto|cloud|datacenter (env: CONFLUENCE_DEPLOYMENT)")
	fs.StringVar(&input.JiraURL, "jira-url", "", "Jira base URL (env: JIRA_URL)")
	fs.StringVar(&input.JiraProject, "jira-project", "", "Jira project key (env: JIRA_PROJECT)")
	fs.StringVar(&input.JiraUser, "jira-user", "", "Jira username / email (env: JIRA_USER, fallback: CONFLUENCE_USER)")
	fs.StringVar(&input.JiraToken, "jira-token", "", "Jira API token (env: JIRA_API_TOKEN, fallback: CONFLUENCE_TOKEN)")
	fs.StringVar(&input.JiraDeployment, "jira-deployment", "", "Jira deployment: auto|cloud|datacenter (env: JIRA_DEPLOYMENT)")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "atlassian check: %v\n", err)
		exitCLI(1)
	}

	input.FlagSet = suppliedFlags(fs)
	cfg, err := resolveAtlassianConfigStrict(input, os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "atlassian check: configuration: %v\n", err)
		exitCLI(1)
	}
	out := buildAtlassianCheckOutput(cfg)
	out.ConfigurationComplete = out.Ready
	out.Checked = []string{"configuration completeness only; no authentication, permissions or create checked"}
	if remote {
		createFieldsFile, _ = resolveStringFlagEnvDefault(createFieldsFile, input.FlagSet["jira-create-fields-file"], "JIRA_CREATE_FIELDS_FILE", "", os.Getenv)
		fields, ferr := loadJiraCreateFields(createFieldsFile)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, ferr)
			exitCLI(1)
		}
		report := jira.CheckReadiness(context.Background(), jira.Options{BaseURL: cfg.JiraURL, Username: cfg.JiraUser, APIToken: cfg.JiraToken, Deployment: cfg.JiraDeployment, ProjectKey: cfg.JiraProject, IssueType: issueType, Component: component, CreateFields: fields})
		out.JiraRemote = &report
		out.ConfigurationComplete = report.ConfigurationComplete
		out.Checked = []string{"Jira configuration and bounded read-only permissions/create metadata; Confluence remote readiness and issue creation not checked"}
		out.Ready = report.ChecksPassed
		if strings.TrimSpace(cfg.ConfluenceURL) == "" {
			out.Missing = nil
		}
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "atlassian check: encode: %v\n", err)
		exitCLI(1)
	}
	os.Stdout.Write(data)
	os.Stdout.WriteString("\n")
	if !out.Ready {
		exitCLI(1)
	}
}
