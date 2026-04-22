package entities

// Post-merge policy passes (epic #71 slice 1c-ii). Run AFTER mergeCore so
// the analyst.History on each finding already reflects the union of all
// inputs and any auto-reopen entries the current merge appended.
//
// Two passes are wired here:
//
//   - Finding-level auto-suppression: when a single finding has accumulated
//     N "auto-reopened from fp" history entries — i.e. the analyst confirmed
//     fp, the detection found it again, the analyst confirmed fp again, and
//     so on — write a finding-scoped Suppression so the loop ends. Bounded
//     by FindingFPSuppressionExpiryDays so the finding eventually re-enters
//     triage in case the underlying context (app code, scope) has changed.
//
//   - Rule-level tune-scan tag: aggregate the same fp-reopen count across
//     every finding sharing a pluginId. When the rule-wide total crosses the
//     threshold, tag the matching Definition's Taxonomy.Tags with "tune-scan".
//     That's the queue security engineering reviews to retune detection rules.
//
// Both passes are idempotent: rerunning the same merge does not duplicate
// suppressions or tags.

import (
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

// pipelineAutoSuppressDecidedBy marks suppressions written by this pass so we
// can tell them apart from analyst-written ones. Analyst-written suppressions
// are NEVER overwritten by the pipeline; only an existing pipeline-written
// suppression that has expired is refreshed.
const pipelineAutoSuppressDecidedBy = "pipeline:auto-suppress"

// countFPReopens returns how many AnalystHistoryEntry rows on a finding
// represent "auto-reopened from fp" — i.e. status=open AND priorStatus=fp.
// Each such entry corresponds to one full cycle of: analyst flagged fp →
// detection found it again → pipeline reopened. Counting these is a more
// honest signal than counting all history entries (analyst-driven status
// changes don't currently create history rows).
func countFPReopens(history []AnalystHistoryEntry) int {
	n := 0
	for _, e := range history {
		if strings.EqualFold(strings.TrimSpace(e.Status), "open") &&
			strings.EqualFold(strings.TrimSpace(e.PriorStatus), "fp") {
			n++
		}
	}
	return n
}

// applyFindingFPAutoSuppression walks every finding and writes a
// finding-scoped Suppression when the fp-reopen count meets the threshold.
//
// Skipped when:
//   - policy threshold <= 0 (operator opted out)
//   - the finding already carries an analyst-written Suppression (we never
//     stomp on a human decision; the analyst can clear it themselves)
//   - the finding already carries a pipeline-written Suppression that is
//     still in-window — refresh only after expiry so the cadence is
//     predictable
func applyFindingFPAutoSuppression(ef *EntitiesFile, policy config.TriagePolicy) {
	if policy.FindingFPSuppressionThreshold <= 0 {
		return
	}
	now := time.Now().UTC()
	expires := ""
	if policy.FindingFPSuppressionExpiryDays > 0 {
		expires = now.AddDate(0, 0, policy.FindingFPSuppressionExpiryDays).Format(time.RFC3339)
	}
	nowStr := now.Format(time.RFC3339)
	for i := range ef.Findings {
		f := &ef.Findings[i]
		if f.Analyst == nil || len(f.Analyst.History) == 0 {
			continue
		}
		count := countFPReopens(f.Analyst.History)
		if count < policy.FindingFPSuppressionThreshold {
			continue
		}
		// Respect existing analyst-authored Suppression entirely.
		if f.Suppression != nil &&
			!strings.EqualFold(strings.TrimSpace(f.Suppression.DecidedBy), pipelineAutoSuppressDecidedBy) {
			continue
		}
		// Respect a still-valid pipeline suppression so we don't churn the
		// expiresAt field on every merge.
		if f.Suppression != nil && f.Suppression.ExpiresAt != "" {
			if exp, err := time.Parse(time.RFC3339, f.Suppression.ExpiresAt); err == nil && exp.After(now) {
				continue
			}
		}
		f.Suppression = &Suppression{
			Scope:     "finding",
			Reason:    "auto-suppressed: " + itoa(count) + " confirmed false-positive recurrences exceed threshold",
			DecidedBy: pipelineAutoSuppressDecidedBy,
			DecidedAt: nowStr,
			ExpiresAt: expires,
		}
	}
}

// applyRuleTuneScanTags aggregates fp-reopen counts across every finding
// sharing a pluginId; when the rule-wide total meets the threshold, the
// matching Definition's Taxonomy.Tags receives "tune-scan" (idempotent).
//
// Skipped when policy threshold <= 0 (operator opted out).
func applyRuleTuneScanTags(ef *EntitiesFile, policy config.TriagePolicy) {
	if policy.RuleTuneScanThreshold <= 0 {
		return
	}
	totals := make(map[string]int)
	for _, f := range ef.Findings {
		pid := strings.TrimSpace(f.PluginID)
		if pid == "" || f.Analyst == nil {
			continue
		}
		totals[pid] += countFPReopens(f.Analyst.History)
	}
	if len(totals) == 0 {
		return
	}
	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		pid := strings.TrimSpace(d.PluginID)
		if pid == "" {
			continue
		}
		if totals[pid] < policy.RuleTuneScanThreshold {
			continue
		}
		if d.Taxonomy == nil {
			d.Taxonomy = &Taxonomy{}
		}
		// unionStrings preserves order and de-dupes; safe to call repeatedly.
		d.Taxonomy.Tags = unionStrings(d.Taxonomy.Tags, []string{"tune-scan"})
	}
}

// itoa: tiny local copy so this file doesn't pull in strconv just for a
// single Sprintf in a Reason string. Threshold values are small integers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
