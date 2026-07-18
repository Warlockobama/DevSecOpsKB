package jira

import "strings"

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
