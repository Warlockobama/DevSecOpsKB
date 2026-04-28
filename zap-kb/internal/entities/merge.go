package entities

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/config"
)

// mergeAnalyst performs field-level merge of two Analyst annotations.
// Rules:
//   - If both are nil, return nil.
//   - If one is nil, return a copy of the other.
//   - Status: base wins if non-empty, else add.
//   - Owner: base wins if non-empty, else add.
//   - Notes: base wins if non-empty, else add.
//   - Tags: union of both slices, deduplicated, order-preserving.
//   - TicketRefs: union of both slices, deduplicated, order-preserving.
//   - UpdatedAt: keep the more recent (lexicographic comparison; valid for RFC3339).
func mergeAnalyst(base, add *Analyst) *Analyst {
	if base == nil && add == nil {
		return nil
	}
	if base == nil {
		cp := *add
		return &cp
	}
	if add == nil {
		cp := *base
		return &cp
	}
	out := *base // start from base copy

	if out.Status == "" {
		out.Status = add.Status
	}
	if out.Owner == "" {
		out.Owner = add.Owner
	}
	if out.Notes == "" {
		out.Notes = add.Notes
	}
	if out.Rationale == "" {
		out.Rationale = add.Rationale
	}
	tBase, err1 := time.Parse(time.RFC3339, out.UpdatedAt)
	tAdd, err2 := time.Parse(time.RFC3339, add.UpdatedAt)
	if err1 == nil && err2 == nil {
		if tAdd.After(tBase) {
			out.UpdatedAt = add.UpdatedAt
		}
	} else if out.UpdatedAt < add.UpdatedAt {
		// fallback to lexicographic if either parse fails
		out.UpdatedAt = add.UpdatedAt
	}
	out.Tags = unionStrings(out.Tags, add.Tags)
	out.TicketRefs = unionStrings(out.TicketRefs, add.TicketRefs)
	// PriorStatus: prefer base when set, else add.
	if out.PriorStatus == "" {
		out.PriorStatus = add.PriorStatus
	}
	// AcceptedUntil: base wins if non-empty, else add.
	if out.AcceptedUntil == "" {
		out.AcceptedUntil = add.AcceptedUntil
	}
	// History: union by EntryID. Order is (base entries in original order) then
	// (add entries whose EntryID is new). Seq is preserved from whichever side
	// contributed the entry; cross-side reseq would make the union
	// non-idempotent, so we deliberately leave it alone.
	out.History = unionHistory(out.History, add.History)
	return &out
}

// unionHistory deduplicates AnalystHistoryEntry slices by EntryID. Entries with
// empty EntryID are dropped (callers should always use NewAnalystHistoryEntry).
func unionHistory(a, b []AnalystHistoryEntry) []AnalystHistoryEntry {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]AnalystHistoryEntry, 0, len(a)+len(b))
	for _, e := range a {
		id := strings.TrimSpace(e.EntryID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, e)
	}
	for _, e := range b {
		id := strings.TrimSpace(e.EntryID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

// unionStrings returns a deduplicated union of a and b, preserving order (a first).
func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Merge returns a new EntitiesFile which is the union of base and add, run
// through the merge pipeline with the org's DEFAULT triage policy. Most
// callers should use this; pass an explicit policy via MergeWithPolicy when
// the caller has loaded triage-policy.yaml itself (e.g. cmd/zap-kb/main.go
// calls LoadPolicy once at startup and threads the result through).
//
// Behaviors driven by the policy (epic #71 slice 1c-ii):
//   - AutoReopenOnRecurrence: gate on/off the slice 1b auto-reopen of fp/fixed
//     findings when new occurrences arrive.
//   - FindingFPSuppressionThreshold/ExpiryDays: after N "auto-reopened from fp"
//     history entries on a single finding, the pipeline writes a finding-scoped
//     Suppression so the noisy detection stops nagging the analyst.
//   - RuleTuneScanThreshold: after the same threshold of fp-reopens aggregated
//     across all findings sharing a pluginId, tag the Definition "tune-scan"
//     so security engineering knows to retune the detection rule.
func Merge(base, add EntitiesFile) EntitiesFile {
	return MergeWithPolicy(base, add, config.DefaultPolicy())
}

// MergeWithPolicy is Merge with an explicit operator-tunable policy. See
// internal/config/policy.go for the policy schema.
func MergeWithPolicy(base, add EntitiesFile, policy config.TriagePolicy) EntitiesFile {
	out := mergeCore(base, add, policy)
	applyFindingFPAutoSuppression(&out, policy)
	applyRuleTuneScanTags(&out, policy)
	warnOccurrenceStatusDivergence(&out)
	return out
}

// warnOccurrenceStatusDivergence prints a [merge] warning line for each
// occurrence whose analyst.Status diverges from its parent finding's
// analyst.Status. Both statuses are compared after canonicalisation; the
// warning fires only when both are non-empty and differ. Per #60, occurrence
// status is writable but is NEVER propagated up — the warning makes the
// divergence visible without blocking the merge. Output is sorted by
// occurrence ID so CI logs are deterministic.
func warnOccurrenceStatusDivergence(ef *EntitiesFile) {
	if ef == nil {
		return
	}
	findStatus := make(map[string]string, len(ef.Findings))
	for i := range ef.Findings {
		f := &ef.Findings[i]
		if f.Analyst == nil {
			continue
		}
		s := strings.TrimSpace(CanonicalAnalystStatus(f.Analyst.Status))
		if s != "" {
			findStatus[f.FindingID] = s
		}
	}
	type divergence struct{ occID, occStatus, findingStatus, findingID string }
	var divergences []divergence
	for i := range ef.Occurrences {
		o := &ef.Occurrences[i]
		if o.Analyst == nil {
			continue
		}
		occStatus := strings.TrimSpace(CanonicalAnalystStatus(o.Analyst.Status))
		if occStatus == "" {
			continue
		}
		fs := findStatus[o.FindingID]
		if fs == "" || fs == occStatus {
			continue
		}
		divergences = append(divergences, divergence{
			occID:         o.OccurrenceID,
			occStatus:     occStatus,
			findingStatus: fs,
			findingID:     o.FindingID,
		})
	}
	sort.Slice(divergences, func(i, j int) bool { return divergences[i].occID < divergences[j].occID })
	for _, d := range divergences {
		fmt.Fprintf(os.Stderr, "[merge] warning: occurrence %s status=%q diverges from finding %s status=%q (occurrence status is not propagated)\n",
			d.occID, d.occStatus, d.findingID, d.findingStatus)
	}
}

// mergeCore is the union/merge work; it does NOT apply the post-merge policy
// passes (auto-suppression, tune-scan tagging). Split out so unit tests can
// exercise the auto-reopen gate without dragging the suppression machinery in.
func mergeCore(base, add EntitiesFile, policy config.TriagePolicy) EntitiesFile {
	out := base

	// Index base definitions by id
	defByID := make(map[string]int, len(out.Definitions))
	for i, d := range out.Definitions {
		defByID[strings.TrimSpace(d.DefinitionID)] = i
	}
	// Merge definitions
	for _, nd := range add.Definitions {
		id := strings.TrimSpace(nd.DefinitionID)
		if id == "" {
			continue
		}
		if i, ok := defByID[id]; ok {
			bd := &out.Definitions[i]
			baseOrigin := strings.TrimSpace(bd.Origin)
			addOrigin := strings.TrimSpace(nd.Origin)
			if baseOrigin == "" {
				bd.Origin = DefinitionOriginValue(nd.Origin, firstNonEmptyString(bd.PluginID, nd.PluginID), nd.Detection)
			} else if addOrigin != "" && !strings.EqualFold(baseOrigin, addOrigin) {
				// Tool vs custom definitions must remain distinct. Keeping base
				// for stability, but surface the collision so the analyst can
				// split the definitionId or reclassify the incoming record.
				log.Printf("warning: merge: definitionId %q origin collision — base=%q add=%q; keeping base. Split the definitionId if these represent different detections.", id, baseOrigin, addOrigin)
			}
			// Fill detection at field level so a partial base can receive missing fields from add.
			if nd.Detection != nil {
				if bd.Detection == nil {
					bd.Detection = &Detection{}
				}
				if bd.Detection.LogicType == "" && nd.Detection.LogicType != "" {
					bd.Detection.LogicType = nd.Detection.LogicType
				}
				if bd.Detection.PluginRef == "" && nd.Detection.PluginRef != "" {
					bd.Detection.PluginRef = nd.Detection.PluginRef
				}
				if bd.Detection.RuleSource == "" && nd.Detection.RuleSource != "" {
					bd.Detection.RuleSource = nd.Detection.RuleSource
				}
				if bd.Detection.DocsURL == "" && nd.Detection.DocsURL != "" {
					bd.Detection.DocsURL = nd.Detection.DocsURL
				}
				if bd.Detection.SourceURL == "" && nd.Detection.SourceURL != "" {
					bd.Detection.SourceURL = nd.Detection.SourceURL
				}
				if bd.Detection.MatchReason == "" && nd.Detection.MatchReason != "" {
					bd.Detection.MatchReason = nd.Detection.MatchReason
				}
			}
			// Fill taxonomy at field level so a partial base can receive missing fields from add.
			if nd.Taxonomy != nil {
				if bd.Taxonomy == nil {
					bd.Taxonomy = &Taxonomy{}
				}
				if bd.Taxonomy.CWEID == 0 && nd.Taxonomy.CWEID != 0 {
					bd.Taxonomy.CWEID = nd.Taxonomy.CWEID
				}
				if bd.Taxonomy.CWEName == "" && nd.Taxonomy.CWEName != "" {
					bd.Taxonomy.CWEName = nd.Taxonomy.CWEName
				}
				if bd.Taxonomy.CWEURI == "" && nd.Taxonomy.CWEURI != "" {
					bd.Taxonomy.CWEURI = nd.Taxonomy.CWEURI
				}
				if len(bd.Taxonomy.CAPECIDs) == 0 && len(nd.Taxonomy.CAPECIDs) > 0 {
					cp := make([]int, len(nd.Taxonomy.CAPECIDs))
					copy(cp, nd.Taxonomy.CAPECIDs)
					bd.Taxonomy.CAPECIDs = cp
				}
				for _, ref := range nd.Taxonomy.CAPEC {
					upsertTaxonomyRef(&bd.Taxonomy.CAPEC, ref)
				}
				if len(bd.Taxonomy.ATTACK) == 0 && len(nd.Taxonomy.ATTACK) > 0 {
					bd.Taxonomy.ATTACK = append([]string(nil), nd.Taxonomy.ATTACK...)
				}
				for _, ref := range nd.Taxonomy.ATTACKTechniques {
					upsertTaxonomyRef(&bd.Taxonomy.ATTACKTechniques, ref)
				}
				if len(bd.Taxonomy.OWASPTop10) == 0 && len(nd.Taxonomy.OWASPTop10) > 0 {
					bd.Taxonomy.OWASPTop10 = append([]string(nil), nd.Taxonomy.OWASPTop10...)
				}
				if len(bd.Taxonomy.NIST80053) == 0 && len(nd.Taxonomy.NIST80053) > 0 {
					bd.Taxonomy.NIST80053 = append([]string(nil), nd.Taxonomy.NIST80053...)
				}
				bd.Taxonomy.Tags = unionStrings(bd.Taxonomy.Tags, nd.Taxonomy.Tags)
				if bd.Taxonomy.MappingConfidence == "" && nd.Taxonomy.MappingConfidence != "" {
					bd.Taxonomy.MappingConfidence = nd.Taxonomy.MappingConfidence
				}
				for _, src := range nd.Taxonomy.Sources {
					addTaxonomySource(bd.Taxonomy, src)
				}
			}
			if bd.CVSS == nil && nd.CVSS != nil {
				cvss := *nd.CVSS
				bd.CVSS = &cvss
			}
			// Fill remediation if missing
			if bd.Remediation == nil && nd.Remediation != nil {
				r := *nd.Remediation
				bd.Remediation = &r
			}
		} else {
			// New definition
			nd.Origin = DefinitionOriginValue(nd.Origin, nd.PluginID, nd.Detection)
			out.Definitions = append(out.Definitions, nd)
			defByID[id] = len(out.Definitions) - 1
		}
	}

	// Index findings and occurrences from base
	findByID := make(map[string]int, len(out.Findings))
	for i, f := range out.Findings {
		findByID[strings.TrimSpace(f.FindingID)] = i
	}
	occIdx := make(map[string]int, len(out.Occurrences))
	for i, o := range out.Occurrences {
		occIdx[strings.TrimSpace(o.OccurrenceID)] = i
	}

	// Add findings (dedup by id).
	// For duplicate findings, apply field-level analyst merge so TicketRefs and
	// triage state from both sides are preserved (base fields win, add fills gaps,
	// tags/ticketRefs are unioned via mergeAnalyst).
	for _, nf := range add.Findings {
		id := strings.TrimSpace(nf.FindingID)
		if id == "" {
			continue
		}
		if idx, ok := findByID[id]; ok {
			// Duplicate: merge analyst data rather than silently discarding add's.
			out.Findings[idx].Analyst = mergeAnalyst(out.Findings[idx].Analyst, nf.Analyst)
			continue
		}
		out.Findings = append(out.Findings, nf)
		findByID[id] = len(out.Findings) - 1
	}

	// Add occurrences (dedup by id).
	// For duplicate occurrences, apply field-level analyst merge via mergeAnalyst:
	// base fields win when non-empty; add fills gaps; tags/ticketRefs are unioned.
	// For new occurrences (not in base), include them as-is.
	for _, no := range add.Occurrences {
		oid := strings.TrimSpace(no.OccurrenceID)
		if oid == "" {
			continue
		}
		if i, ok := occIdx[oid]; ok {
			// Duplicate occurrence: apply field-level analyst merge.
			occ := &out.Occurrences[i]
			occ.Analyst = mergeAnalyst(occ.Analyst, no.Analyst)
			continue
		}
		out.Occurrences = append(out.Occurrences, no)
		occIdx[oid] = len(out.Occurrences) - 1
	}

	// Recompute occurrence counts and FirstSeen/LastSeen per finding from merged occurrence set.
	counts := make(map[string]int)
	firstSeen := make(map[string]string)
	lastSeen := make(map[string]string)
	for _, o := range out.Occurrences {
		fid := strings.TrimSpace(o.FindingID)
		counts[fid]++
		ts := strings.TrimSpace(o.ObservedAt)
		if ts != "" {
			if cur, ok := firstSeen[fid]; !ok || ts < cur {
				firstSeen[fid] = ts
			}
			if cur, ok := lastSeen[fid]; !ok || ts > cur {
				lastSeen[fid] = ts
			}
		}
	}
	for i := range out.Findings {
		f := &out.Findings[i]
		fid := strings.TrimSpace(f.FindingID)
		f.Occurrences = counts[fid]
		if fs := firstSeen[fid]; fs != "" {
			f.FirstSeen = fs
		}
		if ls := lastSeen[fid]; ls != "" {
			f.LastSeen = ls
		}
	}

	// Recurrence detection + auto-reopen (epic #71, slice 1b / issue #57).
	//
	// If a finding that had been marked fixed/fp/accepted receives new occurrences
	// in this merge, we always set an advisory RecurrenceInfo.
	//
	// For fp and fixed findings specifically, we additionally transition the
	// analyst status back to "open" and append a deterministic history entry,
	// gated by policy.AutoReopenOnRecurrence (slice 1c-ii made this toggleable).
	// "accepted" is NOT auto-reopened: acceptance is a time-bounded analyst
	// decision (acceptedUntil) handled separately by slice 2.
	{
		suppressedStatuses := map[string]struct{}{
			"fixed": {}, "accepted": {}, "fp": {},
		}
		reopenStatuses := map[string]struct{}{
			"fixed": {}, "fp": {},
		}
		// Collect occurrence IDs that were in base (so new ones came from add).
		baseOccIDs := make(map[string]struct{}, len(base.Occurrences))
		for _, o := range base.Occurrences {
			baseOccIDs[strings.TrimSpace(o.OccurrenceID)] = struct{}{}
		}
		// Map finding IDs from base to their analyst status.
		baseFindStatus := make(map[string]string, len(base.Findings))
		for _, f := range base.Findings {
			if f.Analyst != nil {
				baseFindStatus[strings.TrimSpace(f.FindingID)] = strings.ToLower(strings.TrimSpace(f.Analyst.Status))
			}
		}
		// Find the earliest new occurrence per finding (not in base).
		type newOccInfo struct {
			recurredAt string
			scanLabel  string
		}
		newOccByFinding := make(map[string]newOccInfo)
		for _, o := range out.Occurrences {
			oid := strings.TrimSpace(o.OccurrenceID)
			if _, wasInBase := baseOccIDs[oid]; wasInBase {
				continue
			}
			fid := strings.TrimSpace(o.FindingID)
			ts := strings.TrimSpace(o.ObservedAt)
			cur, exists := newOccByFinding[fid]
			switch {
			case !exists:
				newOccByFinding[fid] = newOccInfo{recurredAt: ts, scanLabel: strings.TrimSpace(o.ScanLabel)}
			case cur.recurredAt == "" && ts != "":
				// Replace a placeholder (no timestamp) with any real timestamp.
				newOccByFinding[fid] = newOccInfo{recurredAt: ts, scanLabel: strings.TrimSpace(o.ScanLabel)}
			case ts != "" && ts < cur.recurredAt:
				// Keep the earliest non-empty timestamp.
				newOccByFinding[fid] = newOccInfo{recurredAt: ts, scanLabel: strings.TrimSpace(o.ScanLabel)}
			}
		}
		// Fallback timestamp: prefer the scan-stable GeneratedAt of the `add`
		// entities file so merge output is deterministic across re-runs of the
		// same input. Only fall back to wall-clock time when GeneratedAt is
		// absent (older imports) — that path will churn but is explicitly opt-out
		// when operators supply a scan-level timestamp.
		now := strings.TrimSpace(add.GeneratedAt)
		if now == "" {
			now = time.Now().UTC().Format(time.RFC3339)
		}
		for i := range out.Findings {
			f := &out.Findings[i]
			fid := strings.TrimSpace(f.FindingID)
			priorStatus := baseFindStatus[fid]
			if _, wasSuppressed := suppressedStatuses[priorStatus]; !wasSuppressed {
				continue
			}
			info, hasNew := newOccByFinding[fid]
			if !hasNew {
				continue
			}
			recurredAt := info.recurredAt
			if recurredAt == "" {
				recurredAt = now
			}
			// Advisory: refresh Recurrence on each detected recurrence so the
			// banner reflects the latest scan — this is Merge()-owned metadata,
			// not analyst state, so stale values from an earlier run would
			// mislead analysts reviewing an `accepted` finding that keeps
			// recurring across scans.
			f.Recurrence = &RecurrenceInfo{
				PriorStatus:    priorStatus,
				RecurredAt:     recurredAt,
				RecurredInScan: info.scanLabel,
			}

			// Auto-reopen for fp/fixed. Skip accepted. Skip entirely when the
			// org has disabled the behavior in triage-policy.yaml.
			if !policy.AutoReopenOnRecurrence {
				continue
			}
			if _, shouldReopen := reopenStatuses[priorStatus]; !shouldReopen {
				continue
			}
			// If the merged analyst state has already moved off fp/fixed (e.g.
			// human manually reopened between merges, or a previous merge
			// already auto-reopened), do not write another entry.
			if f.Analyst == nil {
				// Can't happen if priorStatus is non-empty (we pulled it from a
				// non-nil base Analyst), but defend anyway.
				f.Analyst = &Analyst{}
			}
			currentStatus := strings.ToLower(strings.TrimSpace(f.Analyst.Status))
			if currentStatus != "fp" && currentStatus != "fixed" {
				continue
			}
			owner := strings.TrimSpace(f.Analyst.Owner)
			notes := "auto-reopened: recurrence in scan " + info.scanLabel
			if info.scanLabel == "" {
				notes = "auto-reopened: recurrence detected"
			}
			entry := NewAnalystHistoryEntry(info.scanLabel, "open", priorStatus, owner, notes, recurredAt)
			// History union de-dupes by EntryID, so re-merging the same scan is a no-op.
			f.Analyst.History = unionHistory(f.Analyst.History, []AnalystHistoryEntry{entry})
			f.Analyst.PriorStatus = priorStatus
			f.Analyst.Status = "open"
			f.Analyst.UpdatedAt = recurredAt
		}
	}

	// Stable sort to keep diffs clean
	sort.Slice(out.Definitions, func(i, j int) bool { return out.Definitions[i].PluginID < out.Definitions[j].PluginID })
	sort.Slice(out.Findings, func(i, j int) bool {
		if out.Findings[i].PluginID != out.Findings[j].PluginID {
			return out.Findings[i].PluginID < out.Findings[j].PluginID
		}
		if out.Findings[i].URL != out.Findings[j].URL {
			return out.Findings[i].URL < out.Findings[j].URL
		}
		return out.Findings[i].Method < out.Findings[j].Method
	})
	sort.Slice(out.Occurrences, func(i, j int) bool {
		if out.Occurrences[i].FindingID != out.Occurrences[j].FindingID {
			return out.Occurrences[i].FindingID < out.Occurrences[j].FindingID
		}
		if out.Occurrences[i].URL != out.Occurrences[j].URL {
			return out.Occurrences[i].URL < out.Occurrences[j].URL
		}
		if out.Occurrences[i].Param != out.Occurrences[j].Param {
			return out.Occurrences[i].Param < out.Occurrences[j].Param
		}
		return out.Occurrences[i].Evidence < out.Occurrences[j].Evidence
	})

	return out
}
