package confluence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

const (
	analystLogStart = "<!-- kb-analyst-log-start -->"
	analystLogEnd   = "<!-- kb-analyst-log-end -->"
	stateSigClass   = "kb-state-sig"
)

// logSummary carries the most-recent analyst log snapshot per finding,
// used to build the Analyst History rollup table on definition pages.
type logSummary struct {
	FindingID   string
	FindingURL  string // Confluence page URL for linking
	PublishedAt string // RFC3339; from the new or latest log entry
	Risk        string
	JiraCase    string
	JiraStatus  string
}

// findingStateSig returns a compact state fingerprint for a finding.
// Format: "occ=N|risk=X|lastSeen=Y|jira=Z"
// This string is embedded in the page as a hidden span. On the next publish,
// the current sig is compared to the stored one; a mismatch triggers a new log entry.
func findingStateSig(f *entities.Finding, jiraStatus string) string {
	if f == nil {
		return ""
	}
	lastSeen := ""
	if f.LastSeen != "" {
		lastSeen = f.LastSeen
	}
	jiraStatus = strings.TrimSpace(jiraStatus)
	return fmt.Sprintf("occ=%d|risk=%s|lastSeen=%s|jira=%s",
		f.Occurrences,
		strings.TrimSpace(f.Risk),
		lastSeen,
		jiraStatus,
	)
}

// extractAnalystLog returns the content between the analyst log markers.
// Returns "" if the markers are not found.
func extractAnalystLog(body string) string {
	start := strings.Index(body, analystLogStart)
	if start < 0 {
		return ""
	}
	content := body[start+len(analystLogStart):]
	end := strings.Index(content, analystLogEnd)
	if end < 0 {
		return ""
	}
	return content[:end]
}

// extractStateSig extracts the value inside the kb-state-sig hidden span.
// Returns "" if not found.
func extractStateSig(body string) string {
	const openTag = `<span class="kb-state-sig" style="display:none">`
	const closeTag = `</span>`
	start := strings.Index(body, openTag)
	if start < 0 {
		return ""
	}
	rest := body[start+len(openTag):]
	end := strings.Index(rest, closeTag)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// demoteFirstInfoEntry replaces the first ac:name="info" occurrence in existingLog
// with ac:name="expand" so previously-most-recent entries collapse.
func demoteFirstInfoEntry(existingLog string) string {
	const target = `ac:name="info"`
	idx := strings.Index(existingLog, target)
	if idx < 0 {
		return existingLog
	}
	return existingLog[:idx] + `ac:name="expand"` + existingLog[idx+len(target):]
}

// buildLogEntry renders a single analyst log entry in Confluence storage XML.
// isMostRecent=true → info macro (always visible); false → expand macro (collapsed).
func buildLogEntry(f *entities.Finding, ei *entityIndex, jiraBaseURL string, jiraStatusByKey map[string]string, publishedAt string, isMostRecent bool) string {
	if f == nil {
		return ""
	}

	macroName := "expand"
	if isMostRecent {
		macroName = "info"
	}

	// Derive display values
	risk := strings.TrimSpace(f.Risk)
	if risk == "" {
		risk = "Unknown"
	}

	lastSeen := ""
	if f.LastSeen != "" {
		t, err := time.Parse(time.RFC3339, f.LastSeen)
		if err == nil {
			lastSeen = t.Format("2006-01-02")
		} else {
			lastSeen = f.LastSeen
		}
	}

	// Jira: pick primary ticket + status
	jiraCase := ""
	jiraStatus := ""
	if f.Analyst != nil {
		refs := f.Analyst.TicketRefs
		jiraStatus = primaryJiraStatus(refs, jiraStatusByKey)
		_, jiraCase = firstJiraBrowseURL(refs, jiraBaseURL)
		if jiraCase == "" && len(refs) > 0 {
			jiraCase = strings.TrimSpace(refs[0])
		}
	}

	// Scan labels
	scanLabels := ""
	if ei != nil {
		if scans, ok := ei.findingScans[f.FindingID]; ok && len(scans) > 0 {
			scanLabels = strings.Join(scans, ", ")
		}
	}

	// Published date (short)
	publishedShort := publishedAt
	if t, err := time.Parse(time.RFC3339, publishedAt); err == nil {
		publishedShort = t.Format("2006-01-02")
	}

	var b strings.Builder
	b.WriteString(`<ac:structured-macro ac:name="` + macroName + `">`)
	if isMostRecent {
		b.WriteString(`<ac:parameter ac:name="title">Analyst Log — ` + escapeHTML(publishedShort) + `</ac:parameter>`)
	} else {
		b.WriteString(`<ac:parameter ac:name="title">` + escapeHTML(publishedShort) + `</ac:parameter>`)
	}
	b.WriteString(`<ac:rich-text-body>`)
	b.WriteString(`<table><tbody>`)

	// Pre-populated section header row (light blue-grey background)
	b.WriteString(`<tr><th colspan="2" style="background-color:#f4f5f7;">Published details</th></tr>`)

	writeRow := func(key, val string) {
		b.WriteString(`<tr><th style="background-color:#f4f5f7;">` + escapeHTML(key) + `</th><td style="background-color:#f4f5f7;">` + val + `</td></tr>`)
	}

	writeRow("Published", escapeHTML(publishedAt))
	writeRow("Risk", riskStatusMacro(risk))
	writeRow("Occurrences", fmt.Sprintf("%d", f.Occurrences))
	writeRow("Last seen", escapeHTML(lastSeen))

	// Jira case: linked if we have a URL, plain text otherwise
	if jiraCase != "" {
		jiraCellVal := escapeHTML(jiraCase)
		if browseURL, _ := jiraIssueBrowseURL(jiraCase, jiraBaseURL); browseURL != "" {
			jiraCellVal = jiraSmartLink(browseURL, jiraCase, "inline")
		}
		if jiraStatus != "" {
			jiraCellVal += " " + jiraStatusMacro(jiraStatus)
		}
		writeRow("Jira case", jiraCellVal)
	}

	if scanLabels != "" {
		writeRow("Scan", escapeHTML(scanLabels))
	}

	// Analyst fields section (white background, user-editable prompts)
	b.WriteString(`<tr><th colspan="2">Analyst entry</th></tr>`)

	writeAnalystRow := func(key, prompt string) {
		b.WriteString(`<tr><th>` + escapeHTML(key) + `</th><td>` + escapeHTML(prompt) + `</td></tr>`)
	}

	writeAnalystRow("Observation", "(enter observation)")
	writeAnalystRow("Decision", "open | triaged | fp | accepted | fixed")
	writeAnalystRow("Rationale", "(why this decision)")
	writeAnalystRow("Next steps", "(what to do next)")

	b.WriteString(`</tbody></table>`)
	b.WriteString(`</ac:rich-text-body>`)
	b.WriteString(`</ac:structured-macro>`)

	return b.String()
}

// buildAnalystLogSection constructs the complete analyst log block including markers.
// The state signature is stored via the Confluence page properties API (not in the body).
// newEntry is prepended to existingLog; the previous most-recent entry is demoted to expand.
func buildAnalystLogSection(newEntry string, existingLog string) string {
	var b strings.Builder

	b.WriteString(`<p><em>Click <strong>Edit</strong> on this page to fill in the analyst fields in the entry below.</em></p>`)
	b.WriteString("<h2>Analyst Log</h2>")
	b.WriteString(analystLogStart)

	if newEntry != "" {
		b.WriteString(newEntry)
		// Demote previous most-recent entry in existingLog from info → expand
		existingLog = demoteFirstInfoEntry(existingLog)
	}
	b.WriteString(existingLog)

	b.WriteString(analystLogEnd)
	return b.String()
}

// upsertPageProperty stores a string value as a Confluence page content property.
// It handles create (404) vs update (version bump) transparently.
func upsertPageProperty(ctx context.Context, client httpDoer, auth, base, pageID, key, value string) error {
	pageID = strings.TrimSpace(pageID)
	if pageID == "" || key == "" {
		return nil
	}
	propURL := base + "/rest/api/content/" + pageID + "/property/" + key

	// Fetch current version (if any).
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, propURL, nil)
	if err != nil {
		return err
	}
	getReq.Header.Set("Authorization", auth)
	// Use client.Do directly (not doWithRetry) so a 404 "property not found"
	// response is not treated as an error — it means we need to create it.
	getResp, err := client.Do(getReq)
	if err != nil {
		return err
	}
	defer getResp.Body.Close()

	type propPayload struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Version struct {
			Number int `json:"number"`
		} `json:"version"`
	}

	if getResp.StatusCode == http.StatusNotFound {
		// Create new property.
		payload := propPayload{Key: key, Value: value}
		payload.Version.Number = 1
		data, merr := json.Marshal(payload)
		if merr != nil {
			return merr
		}
		postReq, merr := http.NewRequestWithContext(ctx, http.MethodPost,
			base+"/rest/api/content/"+pageID+"/property", strings.NewReader(string(data)))
		if merr != nil {
			return merr
		}
		postReq.Header.Set("Authorization", auth)
		postReq.Header.Set("Content-Type", "application/json")
		postResp, merr := doWithRetry(client, postReq, 3)
		if merr != nil {
			return merr
		}
		defer postResp.Body.Close()
		return nil
	}

	// Parse existing version.
	raw, err := io.ReadAll(io.LimitReader(getResp.Body, 64*1024))
	if err != nil {
		return err
	}
	var existing propPayload
	if err := json.Unmarshal(raw, &existing); err != nil {
		return err
	}
	// Update with version+1.
	payload := propPayload{Key: key, Value: value}
	payload.Version.Number = existing.Version.Number + 1
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, propURL, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	putReq.Header.Set("Authorization", auth)
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := doWithRetry(client, putReq, 3)
	if err != nil {
		return err
	}
	defer putResp.Body.Close()
	return nil
}

// fetchPageProperty retrieves a string value from a Confluence page content property.
// Returns "" if the property does not exist (404) or on any error.
func fetchPageProperty(ctx context.Context, client httpDoer, auth, base, pageID, key string) string {
	pageID = strings.TrimSpace(pageID)
	if pageID == "" || key == "" {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/rest/api/content/"+pageID+"/property/"+key, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", auth)
	// Use client.Do directly so 404 (property absent) is handled gracefully.
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode == http.StatusNotFound {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ""
	}
	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return ""
	}
	return result.Value
}

// buildAnalystHistorySection renders the Analyst History rollup table for a
// definition page. Returns "" if summaries is empty.
func buildAnalystHistorySection(summaries []logSummary, jiraBaseURL string) string {
	if len(summaries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<h2>Analyst History</h2>`)
	b.WriteString(`<table><tbody>`)
	b.WriteString(`<tr><th>Finding</th><th>Last entry</th><th>Risk</th><th>Jira case</th><th>Status</th></tr>`)
	for _, s := range summaries {
		// Finding link
		findingCell := escapeHTML(s.FindingID)
		if s.FindingURL != "" {
			findingCell = `<a href="` + escapeAttr(s.FindingURL) + `">` + escapeHTML(s.FindingID) + `</a>`
		}

		// Published date (short)
		publishedShort := s.PublishedAt
		if t, err := time.Parse(time.RFC3339, s.PublishedAt); err == nil {
			publishedShort = t.Format("2006-01-02")
		}

		// Jira case — link if URL resolvable
		jiraCaseCell := escapeHTML(s.JiraCase)
		if s.JiraCase != "" {
			if browseURL, _ := jiraIssueBrowseURL(s.JiraCase, jiraBaseURL); browseURL != "" {
				jiraCaseCell = `<a href="` + escapeAttr(browseURL) + `">` + escapeHTML(s.JiraCase) + `</a>`
			}
		}

		b.WriteString(`<tr><td>` + findingCell + `</td>`)
		b.WriteString(`<td>` + escapeHTML(publishedShort) + `</td>`)
		b.WriteString(`<td>` + riskStatusMacro(s.Risk) + `</td>`)
		b.WriteString(`<td>` + jiraCaseCell + `</td>`)
		b.WriteString(`<td>` + jiraStatusMacro(s.JiraStatus) + `</td></tr>`)
	}
	b.WriteString(`</tbody></table>`)
	return b.String()
}

// fetchPageStorageBody retrieves the storage body of a Confluence page by ID.
// Uses io.LimitReader to cap at 2 MiB — same pattern as pull.go / fetchPageBody.
func fetchPageStorageBody(ctx context.Context, client httpDoer, auth, base, pageID string) (string, error) {
	pageID = strings.TrimSpace(pageID)
	if pageID == "" {
		return "", fmt.Errorf("fetchPageStorageBody: empty page ID")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/rest/api/content/"+pageID+"?expand=body.storage", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", auth)

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	const maxBodyBytes = 2 << 20 // 2 MiB
	lr := io.LimitReader(resp.Body, maxBodyBytes+1)
	raw, err := io.ReadAll(lr)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if len(raw) > maxBodyBytes {
		return "", fmt.Errorf("confluence page body exceeds %d bytes, refusing to parse", maxBodyBytes)
	}

	var result struct {
		Body struct {
			Storage struct {
				Value string `json:"value"`
			} `json:"storage"`
		} `json:"body"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("decode page response: %w", err)
	}
	return result.Body.Storage.Value, nil
}

// buildLogSummaryForFinding builds a logSummary for a finding. publishedAt is the
// timestamp of the new entry (if one was created); otherwise the existing log is
// scanned for the most-recent published timestamp (not yet implemented — uses publishedAt).
func buildLogSummaryForFinding(f *entities.Finding, jiraBaseURL string, jiraStatusByKey map[string]string, publishedAt, _ string) logSummary {
	if f == nil {
		return logSummary{}
	}
	jiraCase := ""
	jiraStatus := ""
	if f.Analyst != nil {
		jiraStatus = primaryJiraStatus(f.Analyst.TicketRefs, jiraStatusByKey)
		_, jiraCase = firstJiraBrowseURL(f.Analyst.TicketRefs, jiraBaseURL)
		if jiraCase == "" && len(f.Analyst.TicketRefs) > 0 {
			jiraCase = strings.TrimSpace(f.Analyst.TicketRefs[0])
		}
	}
	return logSummary{
		FindingID:   f.FindingID,
		PublishedAt: publishedAt,
		Risk:        strings.TrimSpace(f.Risk),
		JiraCase:    jiraCase,
		JiraStatus:  jiraStatus,
	}
}
