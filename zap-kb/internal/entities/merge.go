package entities

import (
	"sort"
	"strings"
	"time"
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
	return &out
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

// Merge returns a new EntitiesFile which is the union of base and add.
// - Definitions: union by definitionId; prefer base; fill missing Detection/Taxonomy/Remediation from add when absent.
// - Findings: union by findingId; prefer base fields; occurrenceCount is recomputed.
// - Occurrences: union by occurrenceId (dedup), then sorted.
func Merge(base, add EntitiesFile) EntitiesFile {
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
				if bd.Taxonomy.CWEURI == "" && nd.Taxonomy.CWEURI != "" {
					bd.Taxonomy.CWEURI = nd.Taxonomy.CWEURI
				}
				if len(bd.Taxonomy.CAPECIDs) == 0 && len(nd.Taxonomy.CAPECIDs) > 0 {
					cp := make([]int, len(nd.Taxonomy.CAPECIDs))
					copy(cp, nd.Taxonomy.CAPECIDs)
					bd.Taxonomy.CAPECIDs = cp
				}
				if len(bd.Taxonomy.ATTACK) == 0 && len(nd.Taxonomy.ATTACK) > 0 {
					bd.Taxonomy.ATTACK = append([]string(nil), nd.Taxonomy.ATTACK...)
				}
				if len(bd.Taxonomy.OWASPTop10) == 0 && len(nd.Taxonomy.OWASPTop10) > 0 {
					bd.Taxonomy.OWASPTop10 = append([]string(nil), nd.Taxonomy.OWASPTop10...)
				}
				if len(bd.Taxonomy.NIST80053) == 0 && len(nd.Taxonomy.NIST80053) > 0 {
					bd.Taxonomy.NIST80053 = append([]string(nil), nd.Taxonomy.NIST80053...)
				}
				bd.Taxonomy.Tags = unionStrings(bd.Taxonomy.Tags, nd.Taxonomy.Tags)
			}
			// Fill remediation if missing
			if bd.Remediation == nil && nd.Remediation != nil {
				r := *nd.Remediation
				bd.Remediation = &r
			}
		} else {
			// New definition
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

	// Add findings (if new)
	for _, nf := range add.Findings {
		id := strings.TrimSpace(nf.FindingID)
		if id == "" {
			continue
		}
		if _, ok := findByID[id]; ok {
			// keep base finding; counts will be recomputed
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
