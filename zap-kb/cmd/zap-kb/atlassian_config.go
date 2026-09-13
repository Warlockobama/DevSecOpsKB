package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type atlassianConfigInput struct {
	ConfluenceURL        string
	ConfluenceSpace      string
	ConfluenceUser       string
	ConfluenceToken      string
	ConfluenceDeployment string
	JiraURL              string
	JiraProject          string
	JiraUser             string
	JiraToken            string
	JiraDeployment       string
	// FlagSet records flags which were supplied by the caller. A supplied empty
	// flag is intentional and must not silently fall back to an environment
	// value. Callers which build this struct directly may omit FlagSet: nonempty
	// values retain the historical meaning of an explicit flag.
	FlagSet map[string]bool
}

type atlassianConfig struct {
	ConfluenceURL              string
	ConfluenceURLSource        string
	ConfluenceSpace            string
	ConfluenceSpaceSource      string
	ConfluenceUser             string
	ConfluenceUserSource       string
	ConfluenceToken            string
	ConfluenceTokenSource      string
	ConfluenceDeployment       string
	ConfluenceDeploymentSource string
	JiraURL                    string
	JiraURLSource              string
	JiraProject                string
	JiraProjectSource          string
	JiraUser                   string
	JiraUserSource             string
	JiraToken                  string
	JiraTokenSource            string
	JiraDeployment             string
	JiraDeploymentSource       string
}

type atlassianTargets struct {
	ConfluenceURL        string `json:"confluenceUrl,omitempty"`
	ConfluenceSpace      string `json:"confluenceSpace,omitempty"`
	ConfluenceDeployment string `json:"confluenceDeployment,omitempty"`
	JiraURL              string `json:"jiraUrl,omitempty"`
	JiraProject          string `json:"jiraProject,omitempty"`
	JiraDeployment       string `json:"jiraDeployment,omitempty"`
}

type atlassianTargetSources struct {
	ConfluenceURL        string `json:"confluenceUrl"`
	ConfluenceSpace      string `json:"confluenceSpace"`
	ConfluenceDeployment string `json:"confluenceDeployment"`
	JiraURL              string `json:"jiraUrl"`
	JiraProject          string `json:"jiraProject"`
	JiraDeployment       string `json:"jiraDeployment"`
}

type atlassianCredentialSources struct {
	ConfluenceUser  string `json:"confluenceUser"`
	ConfluenceToken string `json:"confluenceToken"`
	JiraUser        string `json:"jiraUser"`
	JiraToken       string `json:"jiraToken"`
}

type atlassianCheckOutput struct {
	Ready             bool                       `json:"ready"`
	Missing           []string                   `json:"missing"`
	Targets           atlassianTargets           `json:"targets"`
	TargetSources     atlassianTargetSources     `json:"targetSources"`
	CredentialSources atlassianCredentialSources `json:"credentialSources"`
}

type atlassianPublishSummary struct {
	GeneratedAt       string                      `json:"generatedAt"`
	Targets           atlassianTargets            `json:"targets"`
	CredentialSources atlassianCredentialSources  `json:"credentialSources"`
	Confluence        *publishConfluenceSummary   `json:"confluence,omitempty"`
	Jira              *publishJiraSummary         `json:"jira,omitempty"`
	EvidenceLinks     *publishEvidenceLinkSummary `json:"evidenceLinks,omitempty"`
}

type publishConfluenceSummary struct {
	Created int `json:"created"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

type publishJiraSummary struct {
	Created  int `json:"created"`
	Skipped  int `json:"skipped"`
	Errors   int `json:"errors"`
	Relinked int `json:"relinked"`
}

type publishEvidenceLinkSummary struct {
	Added   int `json:"added"`
	Skipped int `json:"skipped"`
	Errors  int `json:"errors"`
}

// resolveAtlassianConfig preserves the package-level compatibility helper used
// by existing callers. CLI entry points use resolveAtlassianConfigStrict so
// invalid operator input stops before side effects.
func resolveAtlassianConfig(input atlassianConfigInput, getenv func(string) string) atlassianConfig {
	cfg, _ := resolveAtlassianConfigStrict(input, getenv)
	return cfg
}

func resolveAtlassianConfigStrict(input atlassianConfigInput, getenv func(string) string) (atlassianConfig, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	cfg := atlassianConfig{}
	cfg.ConfluenceURL, cfg.ConfluenceURLSource = resolveFlagEnv(input.ConfluenceURL, input.supplied("confluence-url", input.ConfluenceURL), "CONFLUENCE_URL", getenv)
	cfg.ConfluenceSpace, cfg.ConfluenceSpaceSource = resolveFlagEnv(input.ConfluenceSpace, input.supplied("confluence-space", input.ConfluenceSpace), "CONFLUENCE_SPACE", getenv)
	cfg.ConfluenceUser, cfg.ConfluenceUserSource = resolveFlagEnv(input.ConfluenceUser, input.supplied("confluence-user", input.ConfluenceUser), "CONFLUENCE_USER", getenv)
	cfg.ConfluenceToken, cfg.ConfluenceTokenSource = resolveFlagEnv(input.ConfluenceToken, input.supplied("confluence-token", input.ConfluenceToken), "CONFLUENCE_TOKEN", getenv)
	cfg.JiraURL, cfg.JiraURLSource = resolveFlagEnv(input.JiraURL, input.supplied("jira-url", input.JiraURL), "JIRA_URL", getenv)
	cfg.JiraProject, cfg.JiraProjectSource = resolveFlagEnv(input.JiraProject, input.supplied("jira-project", input.JiraProject), "JIRA_PROJECT", getenv)
	cfg.JiraUser, cfg.JiraUserSource = resolveFlagEnv(input.JiraUser, input.supplied("jira-user", input.JiraUser), "JIRA_USER", getenv)
	if strings.TrimSpace(cfg.JiraUser) == "" && cfg.JiraUserSource != "flag" && strings.TrimSpace(cfg.ConfluenceUser) != "" {
		cfg.JiraUser = cfg.ConfluenceUser
		cfg.JiraUserSource = "fallback:CONFLUENCE_USER"
	}
	cfg.JiraToken, cfg.JiraTokenSource = resolveFlagEnv(input.JiraToken, input.supplied("jira-token", input.JiraToken), "JIRA_API_TOKEN", getenv)
	if strings.TrimSpace(cfg.JiraToken) == "" && cfg.JiraTokenSource != "flag" && strings.TrimSpace(cfg.ConfluenceToken) != "" {
		cfg.JiraToken = cfg.ConfluenceToken
		cfg.JiraTokenSource = "fallback:CONFLUENCE_TOKEN"
	}
	var err error
	cfg.ConfluenceDeployment, cfg.ConfluenceDeploymentSource, err = resolveDeploymentStrict(input.ConfluenceDeployment, input.supplied("confluence-deployment", input.ConfluenceDeployment), "CONFLUENCE_DEPLOYMENT", cfg.ConfluenceURL, getenv)
	if err != nil {
		return atlassianConfig{}, err
	}
	cfg.JiraDeployment, cfg.JiraDeploymentSource, err = resolveDeploymentStrict(input.JiraDeployment, input.supplied("jira-deployment", input.JiraDeployment), "JIRA_DEPLOYMENT", cfg.JiraURL, getenv)
	if err != nil {
		return atlassianConfig{}, err
	}
	if err := validateOptionalHTTPURL("Confluence URL", cfg.ConfluenceURL); err != nil {
		return atlassianConfig{}, err
	}
	if err := validateOptionalHTTPURL("Jira URL", cfg.JiraURL); err != nil {
		return atlassianConfig{}, err
	}
	return cfg, nil
}

// resolveDeployment resolves a sink's deployment kind ("cloud" or
// "datacenter"). An explicit flag/env value wins ("dc" and "server" are
// datacenter aliases); "auto" or unset falls back to URL detection —
// *.atlassian.net hosts are Cloud, anything else self-hosted Data Center.
// Returns "" when the sink URL is also unset (sink disabled).
func resolveDeployment(flagValue, envKey, sinkURL string, getenv func(string) string) (string, string) {
	deployment, source, _ := resolveDeploymentStrict(flagValue, strings.TrimSpace(flagValue) != "", envKey, sinkURL, getenv)
	return deployment, source
}

func resolveDeploymentStrict(flagValue string, flagSet bool, envKey, sinkURL string, getenv func(string) string) (string, string, error) {
	explicit, source := resolveFlagEnv(flagValue, flagSet, envKey, getenv)
	switch strings.ToLower(explicit) {
	case "cloud":
		return "cloud", source, nil
	case "datacenter", "dc", "server":
		return "datacenter", source, nil
	case "", "auto":
		// fall through to URL detection
	default:
		return "", source, fmt.Errorf("invalid %s value %q: expected auto, cloud, or datacenter", envKey, explicit)
	}
	sinkURL = strings.TrimSpace(sinkURL)
	if sinkURL == "" {
		return "", "unset", nil
	}
	u, err := url.Parse(sinkURL)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", "auto:url", fmt.Errorf("invalid %s URL %q", strings.ToLower(strings.TrimSuffix(envKey, "_DEPLOYMENT")), sinkURL)
	}
	host := strings.ToLower(u.Hostname())
	if host == "atlassian.net" || strings.HasSuffix(host, ".atlassian.net") {
		return "cloud", "auto:url", nil
	}
	return "datacenter", "auto:url", nil
}

func resolveFlagEnv(flagValue string, flagSet bool, envKey string, getenv func(string) string) (string, string) {
	if flagSet {
		return strings.TrimSpace(flagValue), "flag"
	}
	if v := strings.TrimSpace(getenv(envKey)); v != "" {
		return v, "env:" + envKey
	}
	return "", "unset"
}

func (input atlassianConfigInput) supplied(name, value string) bool {
	return input.FlagSet[name] || strings.TrimSpace(value) != ""
}

func validateOptionalHTTPURL(label, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid %s %q: expected an http or https URL", label, value)
	}
	return nil
}

func (cfg atlassianConfig) targets() atlassianTargets {
	return atlassianTargets{
		ConfluenceURL:        strings.TrimSpace(cfg.ConfluenceURL),
		ConfluenceSpace:      strings.TrimSpace(cfg.ConfluenceSpace),
		ConfluenceDeployment: cfg.ConfluenceDeployment,
		JiraURL:              strings.TrimSpace(cfg.JiraURL),
		JiraProject:          strings.TrimSpace(cfg.JiraProject),
		JiraDeployment:       cfg.JiraDeployment,
	}
}

func (cfg atlassianConfig) targetSources() atlassianTargetSources {
	return atlassianTargetSources{
		ConfluenceURL:        cfg.ConfluenceURLSource,
		ConfluenceSpace:      cfg.ConfluenceSpaceSource,
		ConfluenceDeployment: cfg.ConfluenceDeploymentSource,
		JiraURL:              cfg.JiraURLSource,
		JiraProject:          cfg.JiraProjectSource,
		JiraDeployment:       cfg.JiraDeploymentSource,
	}
}

func (cfg atlassianConfig) credentialSources() atlassianCredentialSources {
	return atlassianCredentialSources{
		ConfluenceUser:  cfg.ConfluenceUserSource,
		ConfluenceToken: cfg.ConfluenceTokenSource,
		JiraUser:        cfg.JiraUserSource,
		JiraToken:       cfg.JiraTokenSource,
	}
}

func (cfg atlassianConfig) missingForFullPublish() []string {
	var missing []string
	if strings.TrimSpace(cfg.ConfluenceURL) == "" {
		missing = append(missing, "CONFLUENCE_URL")
	}
	if strings.TrimSpace(cfg.ConfluenceSpace) == "" {
		missing = append(missing, "CONFLUENCE_SPACE")
	}
	// Cloud API tokens only authenticate as Basic email+token, so the user is
	// required. Data Center accepts a bare personal access token as Bearer, so
	// there the user is optional (username+password remains valid too).
	if strings.TrimSpace(cfg.ConfluenceUser) == "" && cfg.ConfluenceDeployment != "datacenter" {
		missing = append(missing, "CONFLUENCE_USER")
	}
	if strings.TrimSpace(cfg.ConfluenceToken) == "" {
		missing = append(missing, "CONFLUENCE_TOKEN")
	}
	if strings.TrimSpace(cfg.JiraURL) == "" {
		missing = append(missing, "JIRA_URL")
	}
	if strings.TrimSpace(cfg.JiraProject) == "" {
		missing = append(missing, "JIRA_PROJECT")
	}
	if strings.TrimSpace(cfg.JiraUser) == "" && cfg.JiraDeployment != "datacenter" {
		missing = append(missing, "JIRA_USER or CONFLUENCE_USER")
	}
	if strings.TrimSpace(cfg.JiraToken) == "" {
		missing = append(missing, "JIRA_API_TOKEN or CONFLUENCE_TOKEN")
	}
	return missing
}

func buildAtlassianCheckOutput(cfg atlassianConfig) atlassianCheckOutput {
	missing := cfg.missingForFullPublish()
	if missing == nil {
		missing = []string{}
	}
	return atlassianCheckOutput{
		Ready:             len(missing) == 0,
		Missing:           missing,
		Targets:           cfg.targets(),
		TargetSources:     cfg.targetSources(),
		CredentialSources: cfg.credentialSources(),
	}
}

func newAtlassianPublishSummary(cfg atlassianConfig) atlassianPublishSummary {
	return atlassianPublishSummary{
		Targets:           cfg.targets(),
		CredentialSources: cfg.credentialSources(),
	}
}

func writeAtlassianPublishSummary(path string, summary atlassianPublishSummary) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	summary.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create publish summary dir: %w", err)
		}
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("encode publish summary: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write publish summary: %w", err)
	}
	return nil
}
