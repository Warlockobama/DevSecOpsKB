package entities

import "strings"

var canonicalAnalystStatuses = map[string]struct{}{
	"open":     {},
	"triaged":  {},
	"fp":       {},
	"accepted": {},
	"fixed":    {},
}

var analystStatusAliases = map[string]string{
	"open":           "open",
	"new":            "open",
	"todo":           "open",
	"to-do":          "open",
	"backlog":        "open",
	"triage":         "triaged",
	"triaged":        "triaged",
	"confirm":        "triaged",
	"confirmed":      "triaged",
	"valid":          "triaged",
	"real":           "triaged",
	"fp":             "fp",
	"false-positive": "fp",
	"falsepositive":  "fp",
	"accepted":       "accepted",
	"risk-accepted":  "accepted",
	"riskaccepted":   "accepted",
	"wont-fix":       "accepted",
	"wontfix":        "accepted",
	"fixed":          "fixed",
	"done":           "fixed",
	"closed":         "fixed",
	"resolved":       "fixed",
	"complete":       "fixed",
	"completed":      "fixed",
	"remediated":     "fixed",
}

// CanonicalAnalystStatus maps common aliases like "confirm" onto the KB's
// canonical workflow statuses. Unknown values are returned lower-cased so
// callers can preserve unexpected inputs without silently discarding them.
func CanonicalAnalystStatus(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return ""
	}
	key := strings.NewReplacer("_", "-", " ", "-", "'", "", "’", "").Replace(lower)
	if mapped, ok := analystStatusAliases[key]; ok {
		return mapped
	}
	return lower
}

// IsCanonicalAnalystStatus reports whether raw is one of the KB's canonical
// workflow statuses after alias normalization.
func IsCanonicalAnalystStatus(raw string) bool {
	_, ok := canonicalAnalystStatuses[CanonicalAnalystStatus(raw)]
	return ok
}

// NormalizeAnalystStatuses canonicalizes analyst status values across findings
// and occurrences so all outputs render the same workflow vocabulary.
func NormalizeAnalystStatuses(ef *EntitiesFile) {
	if ef == nil {
		return
	}
	for i := range ef.Findings {
		normalizeAnalystStatus(ef.Findings[i].Analyst)
	}
	for i := range ef.Occurrences {
		normalizeAnalystStatus(ef.Occurrences[i].Analyst)
	}
}

func normalizeAnalystStatus(a *Analyst) {
	if a == nil {
		return
	}
	a.Status = CanonicalAnalystStatus(a.Status)
}
