package forgejo

import "strings"

// Forgejo core issues only carry a coarse open/closed state, so workflow
// granularity is expressed via labels. mapForgejoStatus collapses (state,
// labels) into one of the canonical KB statuses used by analyst.Status:
//
//	open|triaged|fixed|accepted|fp
//
// Rules (labels win over state so an open issue tagged "false-positive" maps to
// fp rather than open):
//
//	any "false positive" / "fp" label              → fp
//	any "accepted" / "risk-accepted" / "wontfix"   → accepted
//	state closed (no fp/accepted label) or "fixed"/"resolved"/"done" label → fixed
//	any "triaged" / "in progress" / "in review"    → triaged
//	otherwise (open, untagged)                     → open
//
// Returns "" only when state is empty and no label matches, signaling "leave KB
// status unchanged".
func mapForgejoStatus(state string, labels []string) string {
	state = strings.ToLower(strings.TrimSpace(state))

	var fp, accepted, fixed, triaged bool
	for _, l := range labels {
		switch normalizeLabel(l) {
		case "false positive", "fp", "not a bug", "not applicable":
			fp = true
		case "accepted", "risk accepted", "wontfix", "won't fix", "wont fix", "mitigated":
			accepted = true
		case "fixed", "resolved", "done", "completed":
			fixed = true
		case "triaged", "in progress", "in review", "review", "under review":
			triaged = true
		}
	}

	switch {
	case fp:
		return "fp"
	case accepted:
		return "accepted"
	case state == "closed" || fixed:
		return "fixed"
	case triaged:
		return "triaged"
	case state == "open":
		return "open"
	}
	return ""
}

// normalizeLabel lowercases and collapses separators so "risk-accepted",
// "risk_accepted", and "Risk Accepted" all compare equal.
func normalizeLabel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")
	return strings.Join(strings.Fields(s), " ")
}
