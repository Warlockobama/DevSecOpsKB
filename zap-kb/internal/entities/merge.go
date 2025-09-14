package entities

import (
	"sort"
	"strings"
)

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
			// Fill detection if missing
			if bd.Detection == nil && nd.Detection != nil {
				bd.Detection = &Detection{
					LogicType:   nd.Detection.LogicType,
					PluginRef:   nd.Detection.PluginRef,
					RuleSource:  nd.Detection.RuleSource,
					DocsURL:     nd.Detection.DocsURL,
					SourceURL:   nd.Detection.SourceURL,
					MatchReason: nd.Detection.MatchReason,
				}
			}
			// Fill taxonomy if missing
			if bd.Taxonomy == nil && nd.Taxonomy != nil {
				t := *nd.Taxonomy
				bd.Taxonomy = &t
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
	occSeen := make(map[string]struct{}, len(out.Occurrences))
	for _, o := range out.Occurrences {
		occSeen[strings.TrimSpace(o.OccurrenceID)] = struct{}{}
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

	// Add occurrences (dedup by id)
	for _, no := range add.Occurrences {
		oid := strings.TrimSpace(no.OccurrenceID)
		if oid == "" {
			continue
		}
		if _, ok := occSeen[oid]; ok {
			continue
		}
		out.Occurrences = append(out.Occurrences, no)
		occSeen[oid] = struct{}{}
	}

	// Recompute occurrence counts per finding
	counts := make(map[string]int)
	for _, o := range out.Occurrences {
		counts[strings.TrimSpace(o.FindingID)]++
	}
	for i := range out.Findings {
		f := &out.Findings[i]
		f.Occurrences = counts[strings.TrimSpace(f.FindingID)]
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
