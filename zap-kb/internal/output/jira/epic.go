package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// definitionLabel returns the dedup label used to find or create an Epic
// representing a single detection (Definition). Jira labels cannot contain
// colons, so this mirrors findingLabel's hyphen convention.
func definitionLabel(definitionID string) string {
	return "zap-definition-" + strings.TrimSpace(definitionID)
}

// epicSummary returns the Epic title for a detection. Format:
//
//	[ZAP] <alert> (Plugin <pluginID>)
//
// Truncated to 255 chars (Jira summary limit).
func epicSummary(def *entities.Definition) string {
	if def == nil {
		return ""
	}
	name := strings.TrimSpace(def.Alert)
	if name == "" {
		name = strings.TrimSpace(def.Name)
	}
	if name == "" {
		name = def.DefinitionID
	}
	summary := "[ZAP] " + name
	if pid := strings.TrimSpace(def.PluginID); pid != "" {
		summary += " (Plugin " + pid + ")"
	}
	if len(summary) > 255 {
		summary = summary[:252] + "..."
	}
	return summary
}

// epicEvidence summarises the findings + occurrences for a single detection
// so the Epic body can show a scan-time rollup without round-tripping Jira.
// Empty values are rendered conditionally so the section degrades cleanly when
// no entities are passed in (older callers, dry-run, etc.).
type epicEvidence struct {
	FindingCount    int
	OccurrenceCount int
	ScanLabels      []string // distinct, sorted
	FirstSeen       string   // RFC3339, earliest across occurrences
	LastSeen        string   // RFC3339, latest across occurrences
	TopURLs         []string // up to 10 "METHOD url" entries by occurrence count
}

// buildEpicEvidence aggregates findings + occurrences for a definition into
// the rollup struct used by buildEpicDescription. Pass nil/empty slices for
// dry-run or when entity data is unavailable.
func buildEpicEvidence(findings []entities.Finding, occurrences []entities.Occurrence) epicEvidence {
	ev := epicEvidence{}
	if len(findings) == 0 {
		return ev
	}
	findingIDs := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		findingIDs[f.FindingID] = struct{}{}
	}
	ev.FindingCount = len(findings)

	scanSet := make(map[string]struct{})
	urlCounts := make(map[string]int)
	for _, o := range occurrences {
		if _, ok := findingIDs[o.FindingID]; !ok {
			continue
		}
		ev.OccurrenceCount++
		if s := strings.TrimSpace(o.ScanLabel); s != "" {
			scanSet[s] = struct{}{}
		}
		obs := strings.TrimSpace(o.ObservedAt)
		if obs != "" {
			if ev.FirstSeen == "" || obs < ev.FirstSeen {
				ev.FirstSeen = obs
			}
			if obs > ev.LastSeen {
				ev.LastSeen = obs
			}
		}
		method := strings.TrimSpace(o.Method)
		url := strings.TrimSpace(o.URL)
		if url != "" {
			key := strings.TrimSpace(method + " " + url)
			urlCounts[key]++
		}
	}
	for s := range scanSet {
		ev.ScanLabels = append(ev.ScanLabels, s)
	}
	sort.Strings(ev.ScanLabels)

	type uc struct {
		label string
		count int
	}
	var ucs []uc
	for k, v := range urlCounts {
		ucs = append(ucs, uc{k, v})
	}
	sort.Slice(ucs, func(i, j int) bool {
		if ucs[i].count != ucs[j].count {
			return ucs[i].count > ucs[j].count
		}
		return ucs[i].label < ucs[j].label
	})
	limit := 10
	if limit > len(ucs) {
		limit = len(ucs)
	}
	for _, u := range ucs[:limit] {
		ev.TopURLs = append(ev.TopURLs, fmt.Sprintf("%s (×%d)", u.label, u.count))
	}
	return ev
}

// buildEpicDescription renders the detection-level ADF description for the Epic.
// Includes definition summary, CWE link, ZAP docs link, remediation guidance,
// and a scan-time evidence rollup (finding/occurrence counts, scan labels,
// first/last seen, top affected URLs) so the Epic stands alone as the
// detection's system-of-record in Jira.
func buildEpicDescription(def *entities.Definition, ev epicEvidence) adfDoc {
	if def == nil {
		return adfDoc{Version: 1, Type: "doc", Content: []any{}}
	}
	var nodes []any

	if desc := strings.TrimSpace(def.Description); desc != "" {
		nodes = append(nodes, para(textNode(desc)))
	}

	if def.Taxonomy != nil && def.Taxonomy.CWEID > 0 {
		cweURL := fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", def.Taxonomy.CWEID)
		nodes = append(nodes, para(
			textNode("CWE: "),
			linkNode(fmt.Sprintf("CWE-%d", def.Taxonomy.CWEID), cweURL),
		))
	}

	if def.Detection != nil && strings.TrimSpace(def.Detection.DocsURL) != "" {
		nodes = append(nodes, para(
			textNode("ZAP docs: "),
			linkNode(def.Detection.DocsURL, def.Detection.DocsURL),
		))
	}

	// Evidence rollup — only render when at least one finding/occurrence is
	// known. Each row is conditional so partial data degrades gracefully.
	if ev.FindingCount > 0 || ev.OccurrenceCount > 0 {
		nodes = append(nodes, heading(2, "Evidence rollup"))
		var rows []string
		if ev.FindingCount > 0 {
			rows = append(rows, fmt.Sprintf("Findings: %d", ev.FindingCount))
		}
		if ev.OccurrenceCount > 0 {
			rows = append(rows, fmt.Sprintf("Occurrences: %d", ev.OccurrenceCount))
		}
		if len(ev.ScanLabels) > 0 {
			rows = append(rows, "Scans: "+strings.Join(ev.ScanLabels, ", "))
		}
		if ev.FirstSeen != "" {
			rows = append(rows, "First seen: "+ev.FirstSeen)
		}
		if ev.LastSeen != "" {
			rows = append(rows, "Last seen: "+ev.LastSeen)
		}
		for _, r := range rows {
			nodes = append(nodes, para(textNode(r)))
		}
		if len(ev.TopURLs) > 0 {
			nodes = append(nodes, heading(3, "Top affected endpoints"))
			for _, u := range ev.TopURLs {
				nodes = append(nodes, para(textNode("• "+u)))
			}
		}
	}

	if def.Remediation != nil && strings.TrimSpace(def.Remediation.Summary) != "" {
		nodes = append(nodes, heading(2, "Remediation"))
		nodes = append(nodes, para(textNode(strings.TrimSpace(def.Remediation.Summary))))
	}

	nodes = append(nodes, para(
		textNode("Child issues (Stories/Tasks) track each URL-level finding. This Epic is the detection's system-of-record: triage, suppress, or accept here."),
	))

	return adfDoc{Version: 1, Type: "doc", Content: nodes}
}

// ensureEpicForDefinition returns the Epic issue key for the given definition,
// creating one if none exists. Caching is handled by the caller — this function
// always round-trips Jira when invoked (one search + at most one create).
//
// Returns ("", nil) when Epic creation fails in a recoverable way (project
// doesn't allow the Epic issue type, missing permission, etc.). The caller
// should fall back to flat finding creation and warn the user.
func ensureEpicForDefinition(ctx context.Context, client httpDoer, auth, base string, def *entities.Definition, ev epicEvidence, opts Options) (string, error) {
	if def == nil {
		return "", nil
	}
	label := definitionLabel(def.DefinitionID)

	// Search first to see if the Epic already exists.
	if key, err := findExistingEpicByLabel(ctx, client, auth, base, label); err != nil {
		return "", fmt.Errorf("search epic: %w", err)
	} else if key != "" {
		return key, nil
	}

	issueType := strings.TrimSpace(opts.EpicIssueType)
	if issueType == "" {
		issueType = "Epic"
	}

	fields := map[string]any{
		"project":     map[string]string{"key": opts.ProjectKey},
		"summary":     epicSummary(def),
		"issuetype":   map[string]string{"name": issueType},
		"labels":      []string{label, "zap-detection-epic"},
		"description": buildEpicDescription(def, ev),
	}
	if c := strings.TrimSpace(opts.EpicComponent); c != "" {
		fields["components"] = []map[string]string{{"name": c}}
	}

	body := map[string]any{"fields": fields}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal epic: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/3/issue", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("build epic request: %w", err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", fmt.Errorf("post epic: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden {
		// Project likely doesn't support this issue type or the user lacks
		// permission. Return a soft failure so the caller can fall back.
		return "", nil
	}
	if resp.StatusCode != http.StatusCreated {
		return "", jiraHTTPErr(resp)
	}

	var created struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("decode epic response: %w", err)
	}
	return created.Key, nil
}

// findExistingEpicByLabel returns the key of the first issue with the given
// label, or "" when no match is found. Any issuetype matches — we rely on the
// label (which we only apply to Epics) to scope the search.
func findExistingEpicByLabel(ctx context.Context, client httpDoer, auth, base, label string) (string, error) {
	jql := fmt.Sprintf(`labels = "%s"`, label)
	body := map[string]any{
		"jql":        jql,
		"maxResults": 1,
		"fields":     []string{"id", "key"},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/rest/api/3/search/jql", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doWithRetry(client, req, 3)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", jiraHTTPErr(resp)
	}

	var result struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Issues) == 0 {
		return "", nil
	}
	return result.Issues[0].Key, nil
}
