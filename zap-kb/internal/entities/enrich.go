package entities

import (
	"context"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

// EnrichFirstTraffic populates Request/Response snippets for the first occurrence per Finding.
// It uses ZAP's core/view/message with the occurrence SourceID (history id).
// maxBody controls the max bytes captured into BodySnippet.
func EnrichFirstTraffic(ctx context.Context, c *zapclient.Client, ef *EntitiesFile, maxBody int) error {
	if c == nil || ef == nil {
		return nil
	}
	// Index occurrences by finding and by id
	occIdxByID := make(map[string]int, len(ef.Occurrences))
	occsByFind := make(map[string][]int)
	for i, o := range ef.Occurrences {
		occIdxByID[o.OccurrenceID] = i
		occsByFind[o.FindingID] = append(occsByFind[o.FindingID], i)
	}
	// For each finding, enrich the first occurrence if SourceID present
	for _, f := range ef.Findings {
		idxs := occsByFind[f.FindingID]
		if len(idxs) == 0 {
			continue
		}
		i := idxs[0]
		o := ef.Occurrences[i]
		if strings.TrimSpace(o.SourceID) == "" {
			continue
		}
		msg, err := c.GetMessage(ctx, o.SourceID)
		if err != nil {
			// best-effort: skip errors
			continue
		}
		// Request
		reqHeaders := parseRawHeaders(msg.RequestHeader)
		reqBody := msg.RequestBody
		ef.Occurrences[i].Request = &HTTPRequest{
			Headers:        reqHeaders,
			BodyBytes:      len(reqBody),
			BodySnippet:    truncateUTF8(reqBody, maxBody),
			RawHeader:      msg.RequestHeader,
			RawHeaderBytes: len(msg.RequestHeader),
		}
		// Response
		respHeaders, status := parseRespHeaders(msg.ResponseHeader)
		respBody := msg.ResponseBody
		ef.Occurrences[i].Response = &HTTPResponse{
			StatusCode:     status,
			Headers:        respHeaders,
			BodyBytes:      len(respBody),
			BodySnippet:    truncateUTF8(respBody, maxBody),
			RawHeader:      msg.ResponseHeader,
			RawHeaderBytes: len(msg.ResponseHeader),
		}
	}
	return nil
}

// EnrichAllTraffic populates Request/Response snippets for every occurrence that
// has a SourceID (ZAP history id). Best-effort: skips errors and continues.
func EnrichAllTraffic(ctx context.Context, c *zapclient.Client, ef *EntitiesFile, maxBody int) error {
	if c == nil || ef == nil {
		return nil
	}
	for i := range ef.Occurrences {
		o := ef.Occurrences[i]
		if strings.TrimSpace(o.SourceID) == "" {
			continue
		}
		msg, err := c.GetMessage(ctx, o.SourceID)
		if err != nil {
			continue
		}
		// Request
		reqHeaders := parseRawHeaders(msg.RequestHeader)
		reqBody := msg.RequestBody
		ef.Occurrences[i].Request = &HTTPRequest{
			Headers:        reqHeaders,
			BodyBytes:      len(reqBody),
			BodySnippet:    truncateUTF8(reqBody, maxBody),
			RawHeader:      msg.RequestHeader,
			RawHeaderBytes: len(msg.RequestHeader),
		}
		// Response
		respHeaders, status := parseRespHeaders(msg.ResponseHeader)
		respBody := msg.ResponseBody
		ef.Occurrences[i].Response = &HTTPResponse{
			StatusCode:     status,
			Headers:        respHeaders,
			BodyBytes:      len(respBody),
			BodySnippet:    truncateUTF8(respBody, maxBody),
			RawHeader:      msg.ResponseHeader,
			RawHeaderBytes: len(msg.ResponseHeader),
		}
	}
	return nil
}

func parseRawHeaders(raw string) []Header {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	var headers []Header
	for i, line := range lines {
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			break
		}
		if i == 0 {
			// request/status line
			headers = append(headers, Header{Name: "_line", Value: line})
			continue
		}
		if p := strings.IndexByte(line, ':'); p > 0 {
			name := strings.TrimSpace(line[:p])
			val := strings.TrimSpace(line[p+1:])
			headers = append(headers, Header{Name: name, Value: val})
		} else {
			headers = append(headers, Header{Name: "_raw", Value: line})
		}
	}
	return headers
}

func parseRespHeaders(raw string) ([]Header, int) {
	h := parseRawHeaders(raw)
	status := 0
	if len(h) > 0 {
		// First header value is status/request line, try to parse status code
		parts := strings.Fields(h[0].Value)
		if len(parts) >= 2 {
			if n, err := strconv.Atoi(parts[1]); err == nil {
				status = n
			}
		}
	}
	return h, status
}

func truncateUTF8(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	// ensure not to break in the middle of a rune
	b := []byte(s)
	if max > len(b) {
		max = len(b)
	}
	for max > 0 && !utf8.Valid(b[:max]) {
		max--
	}
	if max <= 0 {
		return ""
	}
	return string(b[:max])
}

// EnrichDetections populates Definition.Detection by scraping ZAP docs and
// inferring the implementing rule source and logic type. Best-effort.
func EnrichDetections(ctx context.Context, ef *EntitiesFile) {
	if ef == nil {
		return
	}
	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		res, err := zapmeta.ScrapeDetection(ctx, d.PluginID)
		if err != nil || res == nil {
			continue
		}
		if d.Detection == nil {
			d.Detection = &Detection{}
		}
		if strings.TrimSpace(d.Detection.LogicType) == "" {
			d.Detection.LogicType = res.LogicType
		}
		if strings.TrimSpace(d.Detection.PluginRef) == "" {
			d.Detection.PluginRef = res.PluginRef
		}
		if strings.TrimSpace(d.Detection.RuleSource) == "" {
			d.Detection.RuleSource = res.RuleSource
		}
		if strings.TrimSpace(d.Detection.DocsURL) == "" {
			d.Detection.DocsURL = res.DocsURL
		}
		if strings.TrimSpace(d.Detection.SourceURL) == "" {
			d.Detection.SourceURL = res.SourceURL
		}
		// Refresh match reason if previously unknown and we just found a source, or if empty
		if strings.TrimSpace(res.MatchReason) != "" {
			cur := strings.ToLower(strings.TrimSpace(d.Detection.MatchReason))
			if cur == "" || strings.Contains(cur, "no source reference") {
				d.Detection.MatchReason = res.MatchReason
			}
		}
		if strings.TrimSpace(d.Alert) == "" && strings.TrimSpace(res.AlertTitle) != "" {
			d.Alert = res.AlertTitle
		}
		if strings.TrimSpace(d.Name) == "" && strings.TrimSpace(res.AlertTitle) != "" {
			d.Name = res.AlertTitle
		}

		// Merge in references from docs if any (best-effort); do not duplicate.
		if len(res.References) > 0 {
			if d.Remediation == nil {
				d.Remediation = &Remediation{}
			}
			existing := map[string]struct{}{}
			for _, r := range d.Remediation.References {
				existing[strings.TrimSpace(r)] = struct{}{}
			}
			for _, r := range res.References {
				r = strings.TrimSpace(r)
				if r == "" {
					continue
				}
				if _, ok := existing[r]; ok {
					continue
				}
				d.Remediation.References = append(d.Remediation.References, r)
				existing[r] = struct{}{}
			}
		}
	}
}

// EnrichDetectionSummaries populates Detection.Summary/Signals/Defaults by fetching
// the rule class and extracting heuristics. Best-effort; skips on error.
func EnrichDetectionSummaries(ctx context.Context, ef *EntitiesFile) {
	if ef == nil {
		return
	}
	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		if d.Detection == nil {
			continue
		}
		// Skip if we already have a summary
		if strings.TrimSpace(d.Detection.Summary) != "" {
			continue
		}
		code, _ := zapmeta.FetchRuleCode(ctx, d.Detection.RuleSource, d.Detection.SourceURL)
		if strings.TrimSpace(code) == "" {
			continue
		}
		rs := zapmeta.SummarizeRule(code)
		// Build a compact summary
		var parts []string
		lt := strings.TrimSpace(d.Detection.LogicType)
		if lt == "" {
			lt = "unknown"
		}
		parts = append(parts, strings.Title(lt))
		if len(rs.Headers) > 0 {
			// show up to 3 headers
			max := 3
			if len(rs.Headers) < max {
				max = len(rs.Headers)
			}
			parts = append(parts, "checks headers: "+strings.Join(rs.Headers[:max], ", "))
		}
		if len(rs.Patterns) > 0 {
			parts = append(parts, "uses regex patterns")
		}
		if rs.Evidence {
			parts = append(parts, "sets evidence")
		}
		if rs.Threshold != "" {
			parts = append(parts, "threshold: "+rs.Threshold)
		}
		if rs.Strength != "" {
			parts = append(parts, "strength: "+rs.Strength)
		}
		d.Detection.Summary = strings.Join(parts, "; ")
		if len(rs.Headers) > 0 || len(rs.Patterns) > 0 {
			// signals: include headers and up to 2 regexes (truncated)
			var sigs []string
			for _, h := range rs.Headers {
				sigs = append(sigs, "header:"+h)
			}
			max := 2
			for i, p := range rs.Patterns {
				if i >= max {
					break
				}
				if len(p) > 80 {
					p = p[:80] + "…"
				}
				sigs = append(sigs, "regex:"+p)
			}
			d.Detection.Signals = sigs
		}
		if rs.Threshold != "" || rs.Strength != "" {
			d.Detection.Defaults = &DetectionDefaults{Threshold: rs.Threshold, Strength: rs.Strength}
		}
	}
}
