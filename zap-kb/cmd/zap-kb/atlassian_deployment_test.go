package main

import (
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

func TestResolveDeployment_AutoDetect(t *testing.T) {
	cases := []struct {
		name string
		explicit,
		url,
		want string
	}{
		{"cloud host", "", "https://yourco.atlassian.net", "cloud"},
		{"cloud host with wiki path", "", "https://yourco.atlassian.net/wiki", "cloud"},
		{"self-hosted host", "", "https://jira.example.com", "datacenter"},
		{"self-hosted confluence", "", "https://confluence.example.com", "datacenter"},
		{"atlassian.net lookalike", "", "https://evil-atlassian.net.example.com", "datacenter"},
		{"explicit cloud wins over host", "cloud", "https://jira.example.com", "cloud"},
		{"explicit datacenter", "datacenter", "https://x.atlassian.net", "datacenter"},
		{"dc alias", "dc", "https://x.atlassian.net", "datacenter"},
		{"server alias", "server", "https://x.atlassian.net", "datacenter"},
		{"auto keyword", "auto", "https://jira.example.com", "datacenter"},
		{"unset url", "", "", ""},
	}
	for _, tc := range cases {
		got, _ := resolveDeployment(tc.explicit, "TEST_DEPLOYMENT", tc.url, noEnv)
		if got != tc.want {
			t.Errorf("%s: resolveDeployment(%q, url=%q) = %q, want %q", tc.name, tc.explicit, tc.url, got, tc.want)
		}
	}
}

func TestAtlassianCheck_DataCenterPATDoesNotRequireUser(t *testing.T) {
	env := map[string]string{
		"CONFLUENCE_URL":   "https://confluence.example.com",
		"CONFLUENCE_SPACE": "SECKB",
		"CONFLUENCE_TOKEN": "conf-pat",
		"JIRA_URL":         "https://jira.example.com",
		"JIRA_PROJECT":     "SEC",
		"JIRA_API_TOKEN":   "jira-pat",
	}
	cfg := resolveAtlassianConfig(atlassianConfigInput{}, func(k string) string { return env[k] })
	if cfg.ConfluenceDeployment != "datacenter" || cfg.JiraDeployment != "datacenter" {
		t.Fatalf("expected datacenter auto-detect, got confluence=%q jira=%q",
			cfg.ConfluenceDeployment, cfg.JiraDeployment)
	}
	if missing := cfg.missingForFullPublish(); len(missing) != 0 {
		t.Errorf("DC PAT config should be ready, missing: %v", missing)
	}
}

func TestAtlassianCheck_CloudStillRequiresUser(t *testing.T) {
	env := map[string]string{
		"CONFLUENCE_URL":   "https://yourco.atlassian.net/wiki",
		"CONFLUENCE_SPACE": "SECKB",
		"CONFLUENCE_TOKEN": "token",
		"JIRA_URL":         "https://yourco.atlassian.net",
		"JIRA_PROJECT":     "SEC",
	}
	cfg := resolveAtlassianConfig(atlassianConfigInput{}, func(k string) string { return env[k] })
	missing := cfg.missingForFullPublish()
	joined := strings.Join(missing, ";")
	if !strings.Contains(joined, "CONFLUENCE_USER") {
		t.Errorf("cloud config without user must report CONFLUENCE_USER missing, got: %v", missing)
	}
	if !strings.Contains(joined, "JIRA_USER") {
		t.Errorf("cloud config without user must report JIRA_USER missing, got: %v", missing)
	}
}
