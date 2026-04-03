package entities

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// NormalizeImportJSON coerces type mismatches that arise when importing entities
// JSON produced by external pipelines (e.g., firing-range, nuclei agents) whose
// field types don't exactly match the Go struct types:
//
//   - Definition.wascid: string "2" → number 2
//   - Finding/Occurrence.riskcode: number 4 → string "4"
//   - HTTPRequest/HTTPResponse.headers: []string → [{name,value}]
//
// Returns the normalized JSON bytes ready for json.Unmarshal into EntitiesFile.
func NormalizeImportJSON(data []byte) ([]byte, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("normalize: unmarshal: %w", err)
	}

	if defs, ok := toSlice(raw["definitions"]); ok {
		for _, item := range defs {
			if def, ok := item.(map[string]interface{}); ok {
				normalizeWASCID(def)
			}
		}
	}
	for _, key := range []string{"findings", "occurrences"} {
		if items, ok := toSlice(raw[key]); ok {
			for _, item := range items {
				if obj, ok := item.(map[string]interface{}); ok {
					normalizeRiskCode(obj)
					if key == "occurrences" {
						normalizeHTTPBlock(obj, "request")
						normalizeHTTPBlock(obj, "response")
					}
				}
			}
		}
	}

	return json.Marshal(raw)
}

// normalizeWASCID converts wascid string → number.
func normalizeWASCID(def map[string]interface{}) {
	v, ok := def["wascid"]
	if !ok {
		return
	}
	switch val := v.(type) {
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			delete(def, "wascid")
			return
		}
		if n, err := strconv.Atoi(s); err == nil {
			def["wascid"] = float64(n)
		}
	}
}

// normalizeRiskCode converts riskcode number → string.
func normalizeRiskCode(obj map[string]interface{}) {
	v, ok := obj["riskcode"]
	if !ok {
		return
	}
	switch val := v.(type) {
	case float64:
		obj["riskcode"] = strconv.Itoa(int(val))
	case json.Number:
		obj["riskcode"] = val.String()
	}
}

// normalizeHTTPBlock converts headers []string → [{name, value}] within
// request or response sub-objects.
func normalizeHTTPBlock(occ map[string]interface{}, key string) {
	block, ok := occ[key]
	if !ok {
		return
	}
	obj, ok := block.(map[string]interface{})
	if !ok {
		return
	}
	hdrs, ok := obj["headers"]
	if !ok {
		return
	}
	items, ok := hdrs.([]interface{})
	if !ok {
		return
	}
	var out []interface{}
	for _, h := range items {
		switch val := h.(type) {
		case string:
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
}

func toSlice(v interface{}) ([]interface{}, bool) {
	if v == nil {
		return nil, false
	}
	s, ok := v.([]interface{})
	return s, ok
}
