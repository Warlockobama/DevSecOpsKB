package entities

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapmeta"
)

const minTrafficSnippetBytes = 1024

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
		if !trafficMatchesOccurrence(o, msg) {
			continue
		}
		// Request
		reqHeaders := parseRawHeaders(msg.RequestHeader)
		reqBody := msg.RequestBody
		ef.Occurrences[i].Request = &HTTPRequest{
			Headers:        reqHeaders,
			BodyBytes:      len(reqBody),
			BodySnippet:    trafficRequestSnippet(reqBody, maxBody),
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
			BodySnippet:    trafficResponseSnippet(respBody, o.Risk, maxBody),
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
		if !trafficMatchesOccurrence(o, msg) {
			continue
		}
		// Request
		reqHeaders := parseRawHeaders(msg.RequestHeader)
		reqBody := msg.RequestBody
		ef.Occurrences[i].Request = &HTTPRequest{
			Headers:        reqHeaders,
			BodyBytes:      len(reqBody),
			BodySnippet:    trafficRequestSnippet(reqBody, maxBody),
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
			BodySnippet:    trafficResponseSnippet(respBody, o.Risk, maxBody),
			RawHeader:      msg.ResponseHeader,
			RawHeaderBytes: len(msg.ResponseHeader),
		}
	}
	return nil
}

// EnrichTrafficSelective enriches up to maxPerFinding observations per issue (Finding),
// only for observations at or above minRisk (info|low|medium|high). If totalMax > 0,
// the enrichment stops after that many observations overall. Best-effort on errors.
func EnrichTrafficSelective(ctx context.Context, c *zapclient.Client, ef *EntitiesFile, maxPerFinding int, minRisk string, totalMax int, maxBody int) error {
	if c == nil || ef == nil {
		return nil
	}
	if maxPerFinding <= 0 {
		maxPerFinding = 1
	}
	floor := severityCode(minRisk)

	// Track per-finding counts and global cap
	per := map[string]int{}
	done := 0

	idxs := make([]int, len(ef.Occurrences))
	for i := range ef.Occurrences {
		idxs[i] = i
	}
	sort.SliceStable(idxs, func(i, j int) bool {
		return severityCode(ef.Occurrences[idxs[i]].Risk) > severityCode(ef.Occurrences[idxs[j]].Risk)
	})

	for _, i := range idxs {
		if totalMax > 0 && done >= totalMax {
			break
		}
		o := ef.Occurrences[i]
		// Filter by risk floor
		if severityCode(o.Risk) < floor {
			continue
		}

		if per[o.FindingID] >= maxPerFinding {
			continue
		}
		if strings.TrimSpace(o.SourceID) == "" {
			continue
		}
		msg, err := c.GetMessage(ctx, o.SourceID)
		if err != nil {
			continue
		}
		if !trafficMatchesOccurrence(o, msg) {
			continue
		}
		// Request
		reqHeaders := parseRawHeaders(msg.RequestHeader)
		reqBody := msg.RequestBody
		ef.Occurrences[i].Request = &HTTPRequest{
			Headers:        reqHeaders,
			BodyBytes:      len(reqBody),
			BodySnippet:    trafficRequestSnippet(reqBody, maxBody),
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
			BodySnippet:    trafficResponseSnippet(respBody, o.Risk, maxBody),
			RawHeader:      msg.ResponseHeader,
			RawHeaderBytes: len(msg.ResponseHeader),
		}
		per[o.FindingID]++
		done++
	}
	return nil
}

// severityCode maps common ZAP risk strings to ascending levels.
// Unknown values default to lowest (info).
func severityCode(r string) int {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "critical", "4":
		return 4
	case "high", "3":
		return 3
	case "medium", "2":
		return 2
	case "low", "1":
		return 1
	case "info", "informational", "information", "0":
		return 0
	default:
		return 0
	}
}

func trafficRequestSnippet(body string, max int) string {
	return truncateUTF8(body, trafficSnippetLimit(max))
}

func trafficResponseSnippet(body, risk string, max int) string {
	if severityCode(risk) >= severityCode("high") {
		return body
	}
	return truncateUTF8(body, trafficSnippetLimit(max))
}

// DropMismatchedTraffic removes captured request/response samples whose request
// line points at a different method/URL than the occurrence. This protects
// offline -run-in exports from publishing stale or incorrectly correlated ZAP
// history messages as finding evidence.
func DropMismatchedTraffic(ef *EntitiesFile) int {
	if ef == nil {
		return 0
	}
	dropped := 0
	for i := range ef.Occurrences {
		o := &ef.Occurrences[i]
		if o.Request == nil || strings.TrimSpace(o.Request.RawHeader) == "" {
			continue
		}
		msg := zapclient.Message{RequestHeader: o.Request.RawHeader}
		if !trafficMatchesOccurrence(*o, msg) {
			o.Request = nil
			o.Response = nil
			dropped++
		}
	}
	return dropped
}

func trafficSnippetLimit(max int) int {
	if max <= 0 {
		return max
	}
	if max < minTrafficSnippetBytes {
		return minTrafficSnippetBytes
	}
	return max
}

func parseRawHeaders(raw string) []Header {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	var headers []Header
	for _, line := range lines {
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			break
		}
		if isHTTPStartLine(line) {
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

func trafficMatchesOccurrence(o Occurrence, msg zapclient.Message) bool {
	method, rawURL, ok := requestLineFromHeader(msg.RequestHeader)
	if !ok {
		return true
	}
	occMethod := strings.ToUpper(strings.TrimSpace(o.Method))
	if occMethod != "" && method != "" && occMethod != method {
		return false
	}
	msgURL := requestLineURL(rawURL, msg.RequestHeader)
	occURL, err := url.Parse(strings.TrimSpace(o.URL))
	if err != nil || occURL == nil {
		return true
	}
	if msgURL == nil {
		return true
	}
	if !strings.EqualFold(occURL.Host, msgURL.Host) {
		return false
	}
	occPath := occURL.EscapedPath()
	if occPath == "" {
		occPath = "/"
	}
	msgPath := msgURL.EscapedPath()
	if msgPath == "" {
		msgPath = "/"
	}
	if occPath != msgPath {
		return false
	}
	return occURL.RawQuery == msgURL.RawQuery
}

func requestLineFromHeader(raw string) (method, target string, ok bool) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			return "", "", false
		}
		if !isHTTPRequestLine(line) {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		return strings.ToUpper(parts[0]), parts[1], true
	}
	return "", "", false
}

func requestLineURL(target, rawHeader string) *url.URL {
	u, err := url.Parse(strings.TrimSpace(target))
	if err == nil && u != nil && u.Host != "" {
		return u
	}
	host := trafficHeaderValue(parseRawHeaders(rawHeader), "host")
	if strings.TrimSpace(host) == "" {
		return nil
	}
	if u == nil {
		u = &url.URL{Path: strings.TrimSpace(target)}
	}
	return &url.URL{Scheme: "http", Host: strings.TrimSpace(host), Path: u.Path, RawQuery: u.RawQuery}
}

func trafficHeaderValue(headers []Header, name string) string {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, h := range headers {
		if strings.ToLower(strings.TrimSpace(h.Name)) == want {
			return strings.TrimSpace(h.Value)
		}
	}
	return ""
}

func isHTTPStartLine(line string) bool {
	return isHTTPRequestLine(line) || isHTTPStatusLine(line)
}

func isHTTPRequestLine(line string) bool {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 3 {
		return false
	}
	switch strings.ToUpper(fields[0]) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
	default:
		return false
	}
	return strings.HasPrefix(strings.ToUpper(fields[len(fields)-1]), "HTTP/")
}

func isHTTPStatusLine(line string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "HTTP/")
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

		// Populate CWE taxonomy from scraped/fallback data if not already set.
		if res.CWEID > 0 && (d.Taxonomy == nil || d.Taxonomy.CWEID == 0) {
			if d.Taxonomy == nil {
				d.Taxonomy = &Taxonomy{}
			}
			d.Taxonomy.CWEID = res.CWEID
			d.Taxonomy.CWEURI = res.CWEURI
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

// EnrichCustomTaxonomy applies static taxonomy overrides and false positive guidance
// for custom/internal plugin IDs (e.g., authenticated-* rules) and well-known plugin IDs
// that have FP guidance (e.g., CDM, CSP, CDJSF). Best-effort.
//
// For these KB-owned custom rules the curated CWE and OWASP are authoritative:
// when the entry specifies them they override any scanner-supplied value, so an
// IDOR finding the scanner mislabeled CWE-200 becomes CWE-639/A01 and stays
// consistent even on a JSON round-trip. CAPEC is likewise authoritative;
// ATT&CK remains additive so scanner-provided identifiers are preserved.
//
// Custom rules are KB-owned, so the scanner's CWE is treated as an untrusted
// placeholder: a custom rule with NO curated mapping has its taxonomy blanked
// (rendering "Taxonomy incomplete") rather than publishing the scanner's generic
// CWE. Standard tool plugins (numeric ZAP ids) are never blanked — their scanner
// CWE is authoritative. UnmappedCustomRules reports the gaps for curation.
// isCustomRule reports whether a plugin ID denotes a KB-authored custom rule (a
// named slug such as "nuclei-auth-complaints-exposure") rather than a standard
// tool plugin (a numeric ZAP id like "zap-10098"). It keys off the CANONICAL id
// so the source/"custom-" prefixes are irrelevant — a tool plugin canonicalizes
// to a number, a custom rule to a slug. This is deliberately independent of the
// origin field, which is normalized later in the pipeline than enrichment runs.
func isCustomRule(pluginID string) bool {
	pid := strings.TrimSpace(pluginID)
	if pid == "" {
		return false
	}
	return !isNumericPluginID(zapmeta.CanonicalPluginID(pid))
}

// UnmappedCustomRules returns the distinct, sorted plugin IDs of custom
// (KB-owned) definitions that have no curated taxonomy entry. These are the
// rules whose taxonomy EnrichCustomTaxonomy blanks; the export surfaces them so
// a maintainer knows exactly what to add to the curated map.
func UnmappedCustomRules(defs []Definition) []string {
	seen := map[string]struct{}{}
	var out []string
	for i := range defs {
		d := &defs[i]
		if !isCustomRule(d.PluginID) {
			continue
		}
		if zapmeta.LookupCustomTaxonomy(d.PluginID) != nil {
			continue
		}
		pid := strings.TrimSpace(d.PluginID)
		if pid == "" {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		out = append(out, pid)
	}
	sort.Strings(out)
	return out
}

func EnrichCustomTaxonomy(defs []Definition) {
	for i := range defs {
		d := &defs[i]

		ct := zapmeta.LookupCustomTaxonomy(d.PluginID)
		if ct == nil {
			// No curated mapping. For a custom (KB-owned) rule, discard the
			// scanner's placeholder taxonomy so the gap is visible instead of
			// misleading. Tool plugins keep their scanner taxonomy.
			if isCustomRule(d.PluginID) && d.Taxonomy != nil {
				d.Taxonomy.CWEID = 0
				d.Taxonomy.CWEURI = ""
				d.Taxonomy.CWEName = ""
				d.Taxonomy.OWASPTop10 = nil
				d.Taxonomy.CAPECIDs = nil
				d.Taxonomy.CAPEC = nil
				d.Taxonomy.MappingConfidence = ""
			}
		}

		// Apply custom taxonomy for authenticated-* and other internal rules.
		if ct != nil {
			if d.Taxonomy == nil {
				d.Taxonomy = &Taxonomy{}
			}
			// CWE is authoritative when the curated entry specifies one.
			if ct.CWEID > 0 {
				d.Taxonomy.CWEID = ct.CWEID
				d.Taxonomy.CWEURI = ct.CWEURI
			}
			// CAPEC is authoritative when the curated entry specifies one: replace
			// the IDs and clear any stale resolved refs so EnrichMITRE rebuilds
			// them. This heals a JSON round-trip where the old (wrong) CWE had
			// derived a mismatched CAPEC (e.g. CWE-200→CAPEC-118 on an IDOR
			// finding now corrected to CWE-639). When the entry has no CAPEC we
			// leave the scanner-provided one untouched.
			if len(ct.CAPECIDs) > 0 {
				ids := make([]int, len(ct.CAPECIDs))
				copy(ids, ct.CAPECIDs)
				d.Taxonomy.CAPECIDs = ids
				d.Taxonomy.CAPEC = nil
			}
			if len(d.Taxonomy.ATTACK) == 0 {
				atk := make([]string, len(ct.ATTACK))
				copy(atk, ct.ATTACK)
				d.Taxonomy.ATTACK = atk
			}
			// OWASP is authoritative: a curated category overrides any
			// scanner-derived value so KB corrections take effect.
			if len(ct.OWASPTop10) > 0 {
				owasp := make([]string, len(ct.OWASPTop10))
				copy(owasp, ct.OWASPTop10)
				d.Taxonomy.OWASPTop10 = owasp
			}
		}

		// Apply false positive guidance for well-known plugin IDs.
		if fp := zapmeta.LookupFalsePositiveGuidance(d.PluginID); fp != nil && len(fp.Conditions) > 0 {
			if d.Remediation == nil {
				d.Remediation = &Remediation{}
			}
			if len(d.Remediation.FalsePositiveConditions) == 0 {
				conds := make([]string, len(fp.Conditions))
				copy(conds, fp.Conditions)
				d.Remediation.FalsePositiveConditions = conds
			}
		}
	}
}
