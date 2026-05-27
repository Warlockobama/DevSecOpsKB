package entities

import (
	"sort"
	"strings"
)

// FilterZAPAlertsOnly keeps only scanner-native ZAP alert records. In this KB
// model those are represented by numeric ZAP plugin IDs. Project/custom
// detections that use zap-* aliases are intentionally excluded.
func FilterZAPAlertsOnly(ef EntitiesFile) EntitiesFile {
	out := ef

	keptDefIDs := map[string]struct{}{}
	defsByID := map[string]Definition{}
	for _, d := range ef.Definitions {
		if isNumericPluginID(d.PluginID) {
			defsByID[strings.TrimSpace(d.DefinitionID)] = d
		}
	}

	keptFindIDs := map[string]struct{}{}
	findings := make([]Finding, 0, len(ef.Findings))
	for _, f := range ef.Findings {
		defID := strings.TrimSpace(f.DefinitionID)
		if !isNumericPluginID(f.PluginID) {
			if _, ok := defsByID[defID]; !ok {
				continue
			}
		}
		keptFindIDs[strings.TrimSpace(f.FindingID)] = struct{}{}
		keptDefIDs[defID] = struct{}{}
		f.Occurrences = 0
		f.FirstSeen = ""
		f.LastSeen = ""
		findings = append(findings, f)
	}

	occurrences := make([]Occurrence, 0, len(ef.Occurrences))
	counts := map[string]int{}
	firstSeen := map[string]string{}
	lastSeen := map[string]string{}
	for _, o := range ef.Occurrences {
		findID := strings.TrimSpace(o.FindingID)
		if _, ok := keptFindIDs[findID]; !ok {
			continue
		}
		occurrences = append(occurrences, o)
		counts[findID]++
		if ts := strings.TrimSpace(o.ObservedAt); ts != "" {
			if firstSeen[findID] == "" || ts < firstSeen[findID] {
				firstSeen[findID] = ts
			}
			if lastSeen[findID] == "" || ts > lastSeen[findID] {
				lastSeen[findID] = ts
			}
		}
	}

	filteredFindings := findings[:0]
	for _, f := range findings {
		findID := strings.TrimSpace(f.FindingID)
		if counts[findID] == 0 {
			continue
		}
		f.Occurrences = counts[findID]
		if firstSeen[findID] != "" {
			f.FirstSeen = firstSeen[findID]
		}
		if lastSeen[findID] != "" {
			f.LastSeen = lastSeen[findID]
		}
		filteredFindings = append(filteredFindings, f)
	}

	definitions := make([]Definition, 0, len(defsByID))
	for defID, d := range defsByID {
		if _, ok := keptDefIDs[defID]; ok {
			definitions = append(definitions, d)
		}
	}
	sort.Slice(definitions, func(i, j int) bool {
		return definitions[i].DefinitionID < definitions[j].DefinitionID
	})

	out.SourceTool = "zap"
	out.Definitions = definitions
	out.Findings = filteredFindings
	out.Occurrences = occurrences
	return out
}
