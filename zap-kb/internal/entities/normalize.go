package entities

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ImportNormalization records one documented compatibility conversion. It
// contains only a field path and rule name, never the source value.
type ImportNormalization struct {
	Path string
	Rule string
}

// NormalizeImportJSON coerces type mismatches that arise when importing entities
// JSON produced by external pipelines (e.g., firing-range, nuclei agents) whose
// field types don't exactly match the Go struct types:
//
//   - Definition.wascid: string "2" → number 2
//   - Finding/Occurrence.riskcode: number 4 → string "4"
//   - HTTPRequest/HTTPResponse.headers: []string → [{name,value}]
//   - null top-level collections from historical zap-kb output → []
//
// Returns the normalized JSON bytes ready for json.Unmarshal into EntitiesFile.
func NormalizeImportJSON(data []byte) ([]byte, error) {
	normalized, _, err := NormalizeImportJSONWithReport(data)
	return normalized, err
}

// NormalizeImportJSONWithReport applies the supported legacy conversions and
// reports each affected field so callers can make compatibility handling
// visible without logging evidence values.
func NormalizeImportJSONWithReport(data []byte) ([]byte, []ImportNormalization, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("normalize: invalid JSON")
	}
	var report []ImportNormalization
	for _, key := range []string{"definitions", "findings", "occurrences"} {
		if value, exists := raw[key]; exists && value == nil {
			raw[key] = []interface{}{}
			report = append(report, ImportNormalization{Path: key, Rule: "null-to-empty-array"})
		}
	}

	if defs, ok := toSlice(raw["definitions"]); ok {
		for i, item := range defs {
			if def, ok := item.(map[string]interface{}); ok {
				if rule := normalizeWASCID(def); rule != "" {
					report = append(report, ImportNormalization{Path: fmt.Sprintf("definitions[%d].wascid", i), Rule: rule})
				}
			}
		}
	}
	for _, key := range []string{"findings", "occurrences"} {
		if items, ok := toSlice(raw[key]); ok {
			for i, item := range items {
				if obj, ok := item.(map[string]interface{}); ok {
					if normalizeRiskCode(obj) {
						report = append(report, ImportNormalization{Path: fmt.Sprintf("%s[%d].riskcode", key, i), Rule: "number-to-string"})
					}
					if key == "occurrences" {
						for _, block := range []string{"request", "response"} {
							if normalizeHTTPBlock(obj, block) {
								report = append(report, ImportNormalization{Path: fmt.Sprintf("occurrences[%d].%s.headers", i, block), Rule: "header-lines-to-objects"})
							}
						}
					}
				}
			}
		}
	}

	normalized, err := json.Marshal(raw)
	return normalized, report, err
}

// EnsureCollections makes newly written v1 documents declare empty
// collections as [] instead of null.
func EnsureCollections(ef *EntitiesFile) {
	if ef == nil {
		return
	}
	if ef.Definitions == nil {
		ef.Definitions = []Definition{}
	}
	if ef.Findings == nil {
		ef.Findings = []Finding{}
	}
	if ef.Occurrences == nil {
		ef.Occurrences = []Occurrence{}
	}
}

// normalizeWASCID converts wascid string → number.
func normalizeWASCID(def map[string]interface{}) string {
	v, ok := def["wascid"]
	if !ok {
		return ""
	}
	switch val := v.(type) {
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			delete(def, "wascid")
			return "empty-string-to-omitted"
		}
		if n, err := strconv.Atoi(s); err == nil {
			def["wascid"] = float64(n)
			return "numeric-string-to-number"
		}
	}
	return ""
}

// normalizeRiskCode converts riskcode number → string.
func normalizeRiskCode(obj map[string]interface{}) bool {
	v, ok := obj["riskcode"]
	if !ok {
		return false
	}
	switch val := v.(type) {
	case float64:
		obj["riskcode"] = strconv.FormatFloat(val, 'f', -1, 64)
		return true
	case json.Number:
		obj["riskcode"] = val.String()
		return true
	}
	return false
}

// normalizeHTTPBlock converts headers []string → [{name, value}] within
// request or response sub-objects.
func normalizeHTTPBlock(occ map[string]interface{}, key string) bool {
	block, ok := occ[key]
	if !ok {
		return false
	}
	obj, ok := block.(map[string]interface{})
	if !ok {
		return false
	}
	hdrs, ok := obj["headers"]
	if !ok {
		return false
	}
	items, ok := hdrs.([]interface{})
	if !ok {
		return false
	}
	var out []interface{}
	changed := false
	for _, h := range items {
		switch val := h.(type) {
		case string:
			changed = true
			name, value, _ := strings.Cut(val, ":")
			out = append(out, map[string]interface{}{
				"name":  strings.TrimSpace(name),
				"value": strings.TrimSpace(value),
			})
		default:
			out = append(out, h) // already an object
		}
	}
	obj["headers"] = out
	return changed
}

func toSlice(v interface{}) ([]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	s, ok := v.([]interface{})
	return s, ok
}
