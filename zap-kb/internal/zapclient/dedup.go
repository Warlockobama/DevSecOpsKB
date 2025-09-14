package zapclient

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
)

// AlertKey returns a stable key for a single alert occurrence.
// Fields chosen to distinguish occurrences deterministically.
func AlertKey(a Alert) string {
	parts := []string{
		"p:" + strings.TrimSpace(a.PluginID),
		"u:" + strings.TrimSpace(a.URL),
		"m:" + strings.TrimSpace(a.Method),
		"pa:" + strings.TrimSpace(a.Param),
		"rk:" + strings.TrimSpace(a.RiskCode),
		"cf:" + strings.TrimSpace(a.Confidence),
		"ak:" + strings.TrimSpace(a.Attack),
		"ev:" + strings.TrimSpace(a.Evidence),
	}
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:8]) // short, deterministic
}

func DeduplicateAlerts(in []Alert) []Alert {
	seen := make(map[string]struct{}, len(in))
	out := make([]Alert, 0, len(in))
	for _, a := range in {
		// require a plugin and at least a URL/Param/Evidence to avoid junk rows
		if strings.TrimSpace(a.PluginID) == "" {
			continue
		}
		if strings.TrimSpace(a.URL) == "" && strings.TrimSpace(a.Param) == "" && strings.TrimSpace(a.Evidence) == "" {
			continue
		}
		k := AlertKey(a)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, a)
	}
	// stable sort for reproducibility
	sort.Slice(out, func(i, j int) bool {
		if out[i].PluginID != out[j].PluginID {
			return out[i].PluginID < out[j].PluginID
		}
		if out[i].URL != out[j].URL {
			return out[i].URL < out[j].URL
		}
		if out[i].Param != out[j].Param {
			return out[i].Param < out[j].Param
		}
		return out[i].Evidence < out[j].Evidence
	})
	return out
}
