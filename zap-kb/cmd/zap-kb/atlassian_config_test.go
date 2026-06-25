package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeEnv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

func TestResolveAtlassianConfig_FlagPrecedenceAndEnvRouting(t *testing.T) {
	cfg := resolveAtlassianConfig(atlassianConfigInput{
		ConfluenceURL: "https://flag.example.com/wiki",
		JiraUser:      "jira-flag@example.com",
	}, fakeEnv(map[string]string{
		"CONFLUENCE_URL":   "https://env.example.com/wiki",
		"CONFLUENCE_SPACE": "KB",
		"CONFLUENCE_USER":  "conf-env@example.com",
		"CONFLUENCE_TOKEN": "conf-token",
		"JIRA_URL":         "https://jira.example.com",
		"JIRA_PROJECT":     "KAN",
		"JIRA_USER":        "jira-env@example.com",
		"JIRA_API_TOKEN":   "jira-token",
	}))

	if cfg.ConfluenceURL != "https://flag.example.com/wiki" || cfg.ConfluenceURLSource != "flag" {
		t.Fatalf("ConfluenceURL precedence/source mismatch: %#v", cfg)
	}
	if cfg.ConfluenceSpace != "KB" || cfg.ConfluenceSpaceSource != "env:CONFLUENCE_SPACE" {
		t.Fatalf("ConfluenceSpace env fallback mismatch: %#v", cfg)
	}
	if cfg.JiraURL != "https://jira.example.com" || cfg.JiraURLSource != "env:JIRA_URL" {
		t.Fatalf("JiraURL env fallback mismatch: %#v", cfg)
	}
	if cfg.JiraProject != "KAN" || cfg.JiraProjectSource != "env:JIRA_PROJECT" {
		t.Fatalf("JiraProject env fallback mismatch: %#v", cfg)
	}
	if cfg.JiraUser != "jira-flag@example.com" || cfg.JiraUserSource != "flag" {
		t.Fatalf("JiraUser flag precedence mismatch: %#v", cfg)
	}
	if cfg.JiraToken != "jira-token" || cfg.JiraTokenSource != "env:JIRA_API_TOKEN" {
		t.Fatalf("JiraToken env fallback mismatch: %#v", cfg)
	}
}

func TestResolveAtlassianConfig_SharedJiraCredentialFallback(t *testing.T) {
	cfg := resolveAtlassianConfig(atlassianConfigInput{}, fakeEnv(map[string]string{
		"CONFLUENCE_URL":   "https://tenant.atlassian.net/wiki",
		"CONFLUENCE_SPACE": "KB2",
		"CONFLUENCE_USER":  "shared@example.com",
		"CONFLUENCE_TOKEN": "shared-token",
		"JIRA_URL":         "https://tenant.atlassian.net",
		"JIRA_PROJECT":     "KAN",
	}))

	if cfg.JiraUser != "shared@example.com" {
		t.Fatalf("expected Jira user to inherit Confluence user, got %q", cfg.JiraUser)
	}
	if cfg.JiraUserSource != "fallback:CONFLUENCE_USER" {
		t.Fatalf("unexpected Jira user source: %q", cfg.JiraUserSource)
	}
	if cfg.JiraToken != "shared-token" {
		t.Fatalf("expected Jira token to inherit Confluence token")
	}
	if cfg.JiraTokenSource != "fallback:CONFLUENCE_TOKEN" {
		t.Fatalf("unexpected Jira token source: %q", cfg.JiraTokenSource)
	}
	out := buildAtlassianCheckOutput(cfg)
	if !out.Ready {
		t.Fatalf("expected shared credential config to be ready, missing=%v", out.Missing)
	}
}

func TestBuildAtlassianCheckOutput_MissingRoutingConfig(t *testing.T) {
	cfg := resolveAtlassianConfig(atlassianConfigInput{}, fakeEnv(map[string]string{
		"CONFLUENCE_USER":  "shared@example.com",
		"CONFLUENCE_TOKEN": "shared-token",
	}))
	out := buildAtlassianCheckOutput(cfg)

	if out.Ready {
		t.Fatal("expected preflight to be not ready")
	}
	want := []string{"CONFLUENCE_URL", "CONFLUENCE_SPACE", "JIRA_URL", "JIRA_PROJECT"}
	if strings.Join(out.Missing, ",") != strings.Join(want, ",") {
		t.Fatalf("missing mismatch:\n got: %v\nwant: %v", out.Missing, want)
	}
	if out.CredentialSources.JiraUser != "fallback:CONFLUENCE_USER" {
		t.Fatalf("expected Jira user source fallback, got %q", out.CredentialSources.JiraUser)
	}
	if out.CredentialSources.JiraToken != "fallback:CONFLUENCE_TOKEN" {
		t.Fatalf("expected Jira token source fallback, got %q", out.CredentialSources.JiraToken)
	}
}

func TestAtlassianCheckOutput_RedactsCredentialValues(t *testing.T) {
	cfg := resolveAtlassianConfig(atlassianConfigInput{}, fakeEnv(map[string]string{
		"CONFLUENCE_URL":   "https://tenant.atlassian.net/wiki",
		"CONFLUENCE_SPACE": "KB2",
		"CONFLUENCE_USER":  "shared@example.com",
		"CONFLUENCE_TOKEN": "secret-token-value",
		"JIRA_URL":         "https://tenant.atlassian.net",
		"JIRA_PROJECT":     "KAN",
	}))
	data, err := json.Marshal(buildAtlassianCheckOutput(cfg))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "shared@example.com") {
		t.Fatalf("check output leaked username: %s", text)
	}
	if strings.Contains(text, "secret-token-value") {
		t.Fatalf("check output leaked token: %s", text)
	}
	if !strings.Contains(text, "fallback:CONFLUENCE_TOKEN") {
		t.Fatalf("check output should include redacted source labels: %s", text)
	}
}

func TestWriteAtlassianPublishSummary_RedactedCountsAndSources(t *testing.T) {
	cfg := resolveAtlassianConfig(atlassianConfigInput{}, fakeEnv(map[string]string{
		"CONFLUENCE_URL":   "https://tenant.atlassian.net/wiki",
		"CONFLUENCE_SPACE": "KB2",
		"CONFLUENCE_USER":  "shared@example.com",
		"CONFLUENCE_TOKEN": "secret-token-value",
		"JIRA_URL":         "https://tenant.atlassian.net",
		"JIRA_PROJECT":     "KAN",
	}))
	summary := newAtlassianPublishSummary(cfg)
	summary.Confluence = &publishConfluenceSummary{Created: 1, Updated: 2, Skipped: 3, Errors: 4}
	summary.Jira = &publishJiraSummary{Created: 5, Skipped: 6, Errors: 7, Relinked: 8}
	summary.EvidenceLinks = &publishEvidenceLinkSummary{Added: 9, Skipped: 10, Errors: 11}

	path := filepath.Join(t.TempDir(), "nested", "publish-summary.json")
	if err := writeAtlassianPublishSummary(path, summary); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "shared@example.com") || strings.Contains(text, "secret-token-value") {
		t.Fatalf("publish summary leaked credentials: %s", text)
	}
	if !strings.Contains(text, `"created": 5`) || !strings.Contains(text, `"fallback:CONFLUENCE_TOKEN"`) {
		t.Fatalf("publish summary missing expected counts/source labels: %s", text)
	}
}
