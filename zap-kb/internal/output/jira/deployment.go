package jira

import (
	"net/url"
	"strings"
)

// IsCloudURL recognizes site and scoped-token gateway API roots, including
// roots used with a local mock port. API roots are distinct from browser URLs.
func IsCloudURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if strings.HasSuffix(host, ".atlassian.net") {
		return true
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	return host == "api.atlassian.com" && len(parts) == 3 && parts[0] == "ex" && parts[1] == "jira" && parts[2] != ""
}

// BrowserBase returns a usable human-facing root. A gateway cannot identify
// its tenant's browser hostname: callers must supply the separate site URL.
func BrowserBase(apiBase, siteBase string) string {
	if strings.TrimSpace(siteBase) != "" {
		return strings.TrimRight(siteBase, "/")
	}
	u, err := url.Parse(apiBase)
	if err != nil || strings.EqualFold(u.Hostname(), "api.atlassian.com") {
		return ""
	}
	return strings.TrimRight(apiBase, "/")
}

// Deployment values accepted by Options.Deployment / PullOptions.Deployment.
// Cloud (the default) speaks REST v3 with ADF descriptions; Data Center only
// serves REST v2 with wiki-markup descriptions and has no /search/jql endpoint.
const (
	DeploymentCloud      = "cloud"
	DeploymentDataCenter = "datacenter"
)

// isDataCenter normalizes a deployment string. "datacenter", "dc", and
// "server" (case-insensitive) select Data Center mode; everything else —
// including "" and "cloud" — keeps the Cloud default.
func isDataCenter(deployment string) bool {
	switch strings.ToLower(strings.TrimSpace(deployment)) {
	case DeploymentDataCenter, "dc", "server":
		return true
	}
	return false
}

// issueAPI returns the versioned issue-resource prefix for the deployment,
// e.g. base+"/rest/api/3" (Cloud) or base+"/rest/api/2" (Data Center).
func issueAPI(base string, dc bool) string {
	if dc {
		return base + "/rest/api/2"
	}
	return base + "/rest/api/3"
}

// searchEndpoint returns the JQL search URL for the deployment. Cloud's
// original /rest/api/3/search was removed in favor of /search/jql; Data Center
// still serves the classic POST /rest/api/2/search. Both accept the same
// {jql, maxResults, fields} body and answer with {issues:[{key}]}.
func searchEndpoint(base string, dc bool) string {
	if dc {
		return base + "/rest/api/2/search"
	}
	return base + "/rest/api/3/search/jql"
}
