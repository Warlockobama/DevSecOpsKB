package zapmeta

import "strings"

// TriageGuidance returns ZAP plugin-specific triage tips for the given pluginID.
// Returns nil when no plugin-specific tips are available.
func TriageGuidance(pluginID string) []string {
	switch strings.TrimSpace(pluginID) {
	case "10038": // CSP header not set
		return []string{
			"Check response headers for Content-Security-Policy or meta CSP tags.",
			"If behind a CDN/reverse proxy, verify headers at edge and origin.",
			"Establish a baseline CSP (default-src 'self') and iterate.",
		}
	case "10020": // Missing Anti-clickjacking header
		return []string{
			"Confirm X-Frame-Options or CSP frame-ancestors is present.",
			"Decide SAMEORIGIN vs DENY; prefer frame-ancestors in CSP for modern browsers.",
		}
	default:
		return nil
	}
}
