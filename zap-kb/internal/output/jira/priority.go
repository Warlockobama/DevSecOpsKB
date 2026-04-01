package jira

import "strings"

// riskToPriority maps ZAP risk strings to Jira Cloud priority names.
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

// severityFloor returns a numeric code for risk filtering (matches entities package convention).
func severityFloor(risk string) int {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
