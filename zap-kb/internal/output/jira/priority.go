package jira

import "strings"

// riskToPriority maps ZAP risk strings to Jira Cloud priority names.
// Risk-threshold filtering uses synccore.SeverityFloor.
func riskToPriority(risk string) string {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default: // info, informational, unknown, ""
		return "Lowest"
	}
}
