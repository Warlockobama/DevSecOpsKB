package zapclient

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// AlertKey returns a stable key for a single alert occurrence.
// Fields chosen to distinguish occurrences deterministically.
//
// Evidence and attack strings are normalized before hashing: scanner payloads
// frequently embed dynamic content (timestamps, UUIDs, nonces, long hashes)
// that would otherwise make the "same" logical occurrence hash differently
// across scans — splitting findings and discarding carry-forward analyst
// state. The raw values remain available on the Alert for display; only the
// key input is sanitized.
func AlertKey(a Alert) string {
	parts := []string{
		"p:" + strings.TrimSpace(a.PluginID),
		"u:" + strings.TrimSpace(a.URL),
		"m:" + strings.TrimSpace(a.Method),
		"pa:" + strings.TrimSpace(a.Param),
		"rk:" + strings.TrimSpace(a.RiskCode),
		"cf:" + strings.TrimSpace(a.Confidence),
		"ak:" + normalizeDynamic(a.Attack),
		"ev:" + normalizeDynamic(a.Evidence),
	}
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:8]) // short, deterministic
}

// Patterns that match dynamic content scanners frequently inject into
// attack/evidence strings. Each is replaced with a stable sentinel so two
// scans of the same logical finding produce the same key.
var (
	reISO8601Timestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?`)
	reUUID             = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reLongHex          = regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`)
	reLongDigits       = regexp.MustCompile(`\b\d{10,}\b`) // epoch seconds/ms, long request IDs
)

// normalizeDynamic strips common sources of per-scan drift from an evidence
// or attack string before it feeds a dedup hash. Order matters: timestamps
// must be matched before long-digit runs so the whole timestamp gets a single
// sentinel instead of being partially chewed by the digit rule.
func normalizeDynamic(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = reISO8601Timestamp.ReplaceAllString(s, "<ts>")
	s = reUUID.ReplaceAllString(s, "<uuid>")
	s = reLongHex.ReplaceAllString(s, "<hex>")
	s = reLongDigits.ReplaceAllString(s, "<num>")
	return s
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
