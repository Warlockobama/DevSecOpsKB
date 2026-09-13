package entities

import (
	"fmt"
	"strings"
	"time"
)

const SupportedSchemaVersion = "v1"

// ValidationIssue identifies a structural or referential problem without
// embedding the rejected value. Keeping diagnostics path/category based avoids
// copying evidence, URLs, or analyst notes into logs.
type ValidationIssue struct {
	Path     string
	Category string
}

func (i ValidationIssue) Error() string {
	return fmt.Sprintf("%s: %s", i.Path, i.Category)
}

// ValidationResult is shared by bare-entities and run-artifact import paths.
// Callers should reject the document when Issues is non-empty.
type ValidationResult struct {
	Issues []ValidationIssue
}

func (r ValidationResult) OK() bool { return len(r.Issues) == 0 }

func (r ValidationResult) Err() error {
	if r.OK() {
		return nil
	}
	return r.Issues[0]
}

// Validate checks the typed entities graph. JSON collection presence and type
// are checked by the artifact reader before this function is called.
func Validate(ef EntitiesFile) ValidationResult {
	var result ValidationResult
	add := func(path, category string) {
		result.Issues = append(result.Issues, ValidationIssue{Path: path, Category: category})
	}

	if strings.TrimSpace(ef.SchemaVersion) == "" {
		add("schemaVersion", "missing required version")
	} else if strings.TrimSpace(ef.SchemaVersion) != SupportedSchemaVersion {
		add("schemaVersion", "unsupported version")
	}
	validateTimestamp(&result, "generatedAt", ef.GeneratedAt)

	definitions := make(map[string]Definition, len(ef.Definitions))
	for i, definition := range ef.Definitions {
		path := fmt.Sprintf("definitions[%d]", i)
		id := strings.TrimSpace(definition.DefinitionID)
		if id == "" {
			add(path+".definitionId", "missing required ID")
		} else if id != definition.DefinitionID {
			add(path+".definitionId", "surrounding whitespace")
		} else if _, exists := definitions[id]; exists {
			add(path+".definitionId", "duplicate ID")
		} else {
			definitions[id] = definition
		}
		if strings.TrimSpace(definition.PluginID) == "" {
			add(path+".pluginId", "missing required ID")
		} else if strings.TrimSpace(definition.PluginID) != definition.PluginID {
			add(path+".pluginId", "surrounding whitespace")
		}
	}

	findings := make(map[string]Finding, len(ef.Findings))
	for i, finding := range ef.Findings {
		path := fmt.Sprintf("findings[%d]", i)
		id := strings.TrimSpace(finding.FindingID)
		if id == "" {
			add(path+".findingId", "missing required ID")
		} else if id != finding.FindingID {
			add(path+".findingId", "surrounding whitespace")
		} else if _, exists := findings[id]; exists {
			add(path+".findingId", "duplicate ID")
		} else {
			findings[id] = finding
		}
		if strings.TrimSpace(finding.PluginID) == "" {
			add(path+".pluginId", "missing required ID")
		} else if strings.TrimSpace(finding.PluginID) != finding.PluginID {
			add(path+".pluginId", "surrounding whitespace")
		}
		definitionID := strings.TrimSpace(finding.DefinitionID)
		if definitionID == "" {
			add(path+".definitionId", "missing required reference")
		} else if definitionID != finding.DefinitionID {
			add(path+".definitionId", "surrounding whitespace")
		} else if _, exists := definitions[definitionID]; !exists {
			add(path+".definitionId", "dangling reference")
		} else if definition := definitions[definitionID]; strings.TrimSpace(definition.PluginID) != strings.TrimSpace(finding.PluginID) {
			add(path+".pluginId", "inconsistent with definition reference")
		}
		validateTimestamp(&result, path+".firstSeen", finding.FirstSeen)
		validateTimestamp(&result, path+".lastSeen", finding.LastSeen)
		validateTimestampOrder(&result, path+".firstSeen", finding.FirstSeen, path+".lastSeen", finding.LastSeen)
		validateAnalyst(&result, path+".analyst", finding.Analyst)
		if finding.Suppression != nil {
			validateTimestamp(&result, path+".suppression.decidedAt", finding.Suppression.DecidedAt)
			validateTimestamp(&result, path+".suppression.expiresAt", finding.Suppression.ExpiresAt)
		}
		if finding.Recurrence != nil {
			validateTimestamp(&result, path+".recurrence.recurredAt", finding.Recurrence.RecurredAt)
		}
	}

	occurrences := make(map[string]Occurrence, len(ef.Occurrences))
	for i, occurrence := range ef.Occurrences {
		path := fmt.Sprintf("occurrences[%d]", i)
		id := strings.TrimSpace(occurrence.OccurrenceID)
		if id == "" {
			add(path+".occurrenceId", "missing required ID")
		} else if id != occurrence.OccurrenceID {
			add(path+".occurrenceId", "surrounding whitespace")
		} else if _, exists := occurrences[id]; exists {
			add(path+".occurrenceId", "duplicate ID")
		} else {
			occurrences[id] = occurrence
		}
		definitionID := strings.TrimSpace(occurrence.DefinitionID)
		if definitionID == "" {
			add(path+".definitionId", "missing required reference")
		} else if definitionID != occurrence.DefinitionID {
			add(path+".definitionId", "surrounding whitespace")
		} else if _, exists := definitions[definitionID]; !exists {
			add(path+".definitionId", "dangling reference")
		}
		findingID := strings.TrimSpace(occurrence.FindingID)
		finding, findingExists := findings[findingID]
		if findingID == "" {
			add(path+".findingId", "missing required reference")
		} else if findingID != occurrence.FindingID {
			add(path+".findingId", "surrounding whitespace")
		} else if !findingExists {
			add(path+".findingId", "dangling reference")
		} else if definitionID != "" && strings.TrimSpace(finding.DefinitionID) != definitionID {
			add(path+".definitionId", "inconsistent with finding reference")
		}
		validateTimestamp(&result, path+".observedAt", occurrence.ObservedAt)
		validateAnalyst(&result, path+".analyst", occurrence.Analyst)
	}

	for i, finding := range ef.Findings {
		if finding.Suppression == nil || strings.TrimSpace(finding.Suppression.OccurrenceRef) == "" {
			if finding.Suppression != nil && strings.EqualFold(strings.TrimSpace(finding.Suppression.Scope), "occurrence") {
				add(fmt.Sprintf("findings[%d].suppression.occurrenceRef", i), "missing required reference")
			}
			continue
		}
		occurrence, exists := occurrences[strings.TrimSpace(finding.Suppression.OccurrenceRef)]
		if !exists {
			add(fmt.Sprintf("findings[%d].suppression.occurrenceRef", i), "dangling reference")
		} else if strings.TrimSpace(occurrence.FindingID) != strings.TrimSpace(finding.FindingID) {
			add(fmt.Sprintf("findings[%d].suppression.occurrenceRef", i), "inconsistent with finding reference")
		}
	}

	return result
}

func validateAnalyst(result *ValidationResult, path string, analyst *Analyst) {
	if analyst == nil {
		return
	}
	validateTimestamp(result, path+".updatedAt", analyst.UpdatedAt)
	validateTimestamp(result, path+".acceptedUntil", analyst.AcceptedUntil)
	seenHistoryIDs := make(map[string]struct{}, len(analyst.History))
	for i, entry := range analyst.History {
		entryPath := fmt.Sprintf("%s.history[%d]", path, i)
		id := strings.TrimSpace(entry.EntryID)
		if id == "" {
			result.Issues = append(result.Issues, ValidationIssue{Path: entryPath + ".entryId", Category: "missing required ID"})
		} else if id != entry.EntryID {
			result.Issues = append(result.Issues, ValidationIssue{Path: entryPath + ".entryId", Category: "surrounding whitespace"})
		} else if _, exists := seenHistoryIDs[id]; exists {
			result.Issues = append(result.Issues, ValidationIssue{Path: entryPath + ".entryId", Category: "duplicate ID"})
		} else {
			seenHistoryIDs[id] = struct{}{}
		}
		validateTimestamp(result, entryPath+".updatedAt", entry.UpdatedAt)
	}
}

func validateTimestamp(result *ValidationResult, path, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		result.Issues = append(result.Issues, ValidationIssue{Path: path, Category: "invalid RFC3339 timestamp"})
	}
}

func validateTimestampOrder(result *ValidationResult, firstPath, firstValue, lastPath, lastValue string) {
	first, firstErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(firstValue))
	last, lastErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(lastValue))
	if firstErr == nil && lastErr == nil && first.After(last) {
		result.Issues = append(result.Issues, ValidationIssue{Path: firstPath + "/" + lastPath, Category: "timestamp range is reversed"})
	}
}
