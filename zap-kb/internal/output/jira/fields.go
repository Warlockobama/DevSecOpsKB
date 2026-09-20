package jira

import (
	"fmt"
	"regexp"
)

var issueTypeID = regexp.MustCompile(`^[0-9]+$`)

// ValidateCreateFields prevents customization from changing identity labels,
// generated evidence, project, type, or Jira-owned status/workflow.
func ValidateCreateFields(fields map[string]any) error {
	for field := range fields {
		if customFieldID.MatchString(field) {
			continue
		}
		switch field {
		case "priority", "components", "assignee", "parent", "reporter", "duedate", "fixVersions", "versions", "environment", "security", "timetracking":
			continue
		}
		return fmt.Errorf("jira create-fields: only customfield IDs and supported optional create fields are allowed; identity, evidence and workflow overrides are forbidden")
	}
	return nil
}
