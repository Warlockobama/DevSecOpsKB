package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// Options controls Jira issue export.
type Options struct {
	BaseURL string
	// Username is the account email on Jira Cloud, or the account username on
	// Data Center. Leave empty on Data Center to send APIToken as a Bearer
	// personal access token instead of Basic auth.
	Username string
	// APIToken is the Cloud API token, Data Center password (with Username),
	// or Data Center personal access token (without Username).
	APIToken string
	// Deployment selects the API dialect: DeploymentCloud (default, REST v3 +
	// ADF) or DeploymentDataCenter (REST v2 + wiki markup). "dc" and "server"
	// are accepted aliases for Data Center.
	Deployment   string
	ProjectKey   string
	IssueType    string   // default "Bug"
	Component    string   // optional component name
	ExtraLabels  []string // additional labels beyond zap-finding:<id>
	MinRisk      string   // minimum risk to export: info|low|medium|high (default "medium")
	DryRun       bool
	Concurrency  int           // max parallel requests (default 3, capped at 5)
	Timeout      time.Duration // default 30s
	RequestDelay time.Duration // minimum delay between API requests; default 250ms
	OptInTag     string        // analyst tag that forces Jira export below MinRisk (default "case-ticket")

	// DetectionEpic, when true, creates (or reuses) a parent Epic per Definition
	// and links each finding issue to it via the `parent` field. Epics are
	// dedup'd via the label zap-definition-<definitionID>.
	DetectionEpic bool
	// EpicIssueType overrides the Epic issue type name for projects that use
	// "Initiative" or a custom type. Default "Epic".
	EpicIssueType string
	// EpicComponent is an optional component name applied to detection Epics.
	EpicComponent string

	// UsernameMap maps a KB analyst owner handle (e.g. "alice") to a Jira
	// Cloud accountId. Set by CLI flag -jira-user-map. When a finding's
	// analyst.owner has a mapping, the issue is assigned to that account on
	// create. When the owner is set but no mapping exists, the issue is
	// created unassigned and a stderr warning is emitted (#61).
	UsernameMap map[string]string
	// CreateFields supplies project-specific fields on new finding issues only.
	// Reserved identity, evidence and workflow fields cannot be overridden.
	// A null value omits an optional default such as priority.
	CreateFields map[string]any
}

// httpDoer is an alias for synccore.HTTPDoer, kept so this package's
// signatures and tests don't need renaming after the synccore migration.
type httpDoer = synccore.HTTPDoer

// Summary reports the outcome of an export run.
type Summary struct {
	Diagnostics []publication.Diagnostic
	DryRun      bool
	Created     int
	Skipped     int // already existed
	Errors      int
	TicketKeys  map[string]string // findingID → Jira issue key (KAN-42)
	// EpicKeys maps definitionID → Epic issue key when DetectionEpic is on.
	// Empty when the feature is disabled or failed (see Diagnostics).
	EpicKeys map[string]string
	// Relinked counts existing findings whose `parent` field was retroactively
	// set to a newly-created or pre-existing detection Epic. Useful when an
	// older run created findings before -jira-detection-epic was enabled.
	Relinked int
}

// Export creates Jira issues for each Finding at or above opts.MinRisk, or when an analyst opt-in tag is present.
// Findings that already have a matching issue (by label zap-finding:<findingID>) are skipped.
// Issues are created in parallel up to opts.Concurrency.
func Export(ctx context.Context, ef entities.EntitiesFile, opts Options) (Summary, error) {
	if err := ValidateCreateFields(opts.CreateFields); err != nil {
		return Summary{}, err
	}
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.ProjectKey) == "" ||
		strings.TrimSpace(opts.APIToken) == "" {
		return Summary{}, fmt.Errorf("jira export: missing required fields (base URL, project key, api token)")
	}
	dc := isDataCenter(opts.Deployment)
	var diagnostics []publication.Diagnostic
	epicErrors := 0
	if opts.DetectionEpic && dc {
		// Data Center classic projects link Epic children via the per-instance
		// "Epic Link" custom field, not the Cloud `parent` field — creating the
		// link would 400. Record the unsupported request and continue findings.
		diagnostics = append(diagnostics, publication.Diagnostic{Stage: "epic", Category: "unsupported", Message: "Detection epics require Cloud; Data Center Epic Link configuration is not supported"})
		epicErrors++
		opts.DetectionEpic = false
	}

	issueType := opts.IssueType
	if strings.TrimSpace(issueType) == "" {
		issueType = "Bug"
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 3
	}
	if concurrency > 5 {
		concurrency = 5
	}

	rawClient := &http.Client{Timeout: opts.Timeout}
	if rawClient.Timeout == 0 {
		rawClient.Timeout = 30 * time.Second
	}
	delay := opts.RequestDelay
	if delay == 0 {
		delay = 250 * time.Millisecond
	}
	httpClient := synccore.NewThrottledClient(rawClient, delay)
	auth := synccore.AuthHeader(opts.Username, opts.APIToken)
	base := strings.TrimRight(opts.BaseURL, "/")
	floor := synccore.SeverityFloor(opts.MinRisk)
	if strings.TrimSpace(opts.MinRisk) == "" {
		floor = synccore.SeverityFloor("medium")
	}
	optInTag := strings.TrimSpace(opts.OptInTag)
	if optInTag == "" {
		optInTag = "case-ticket"
	}

	// Index definitions for quick lookup
	defByID := make(map[string]*entities.Definition, len(ef.Definitions))
	for i := range ef.Definitions {
		d := &ef.Definitions[i]
		defByID[d.DefinitionID] = d
	}

	// Pick the most recent occurrence per finding — that becomes the evidence
	// sample rendered into the issue description. Ties fall back to OccurrenceID
	// so the choice is deterministic across runs.
	latestOccByFind := make(map[string]*entities.Occurrence, len(ef.Findings))
	for i := range ef.Occurrences {
		o := &ef.Occurrences[i]
		cur, ok := latestOccByFind[o.FindingID]
		if !ok || occurrenceIsNewer(o, cur) {
			latestOccByFind[o.FindingID] = o
		}
	}

	// Filter findings by minimum risk or explicit analyst opt-in.
	var candidates []entities.Finding
	for _, f := range ef.Findings {
		if synccore.SeverityFloor(f.Risk) >= floor || findingHasOptInTag(f, optInTag) {
			candidates = append(candidates, f)
		}
	}

	if len(candidates) == 0 {
		return Summary{Errors: epicErrors, Diagnostics: diagnostics, DryRun: opts.DryRun}, nil
	}

	if opts.DryRun {
		for _, f := range candidates {
			label := findingLabel(f.FindingID)
			fmt.Printf("[jira] dry-run: would create issue for finding %s (risk=%s url=%s) label=%s\n",
				f.FindingID, f.Risk, f.URL, label)
		}
		if opts.DetectionEpic {
			seen := make(map[string]struct{})
			for _, f := range candidates {
				if _, ok := seen[f.DefinitionID]; ok {
					continue
				}
				seen[f.DefinitionID] = struct{}{}
				def := defByID[f.DefinitionID]
				fmt.Printf("[jira] dry-run: would ensure epic for definition %s (%s) label=%s\n",
					f.DefinitionID, epicSummary(def), definitionLabel(f.DefinitionID))
			}
		}
		return Summary{Skipped: len(candidates), DryRun: true, Errors: epicErrors, Diagnostics: diagnostics}, nil
	}

	// Detection Epics (opt-in). Resolve one Epic key per distinct definition
	// among the candidates so findings can be linked via `parent` below.
	// Failures remain required-stage failures while finding creation proceeds.
	epicKeys := make(map[string]string)
	if opts.DetectionEpic {
		// Pre-bucket findings + occurrences by definitionId so the Epic body
		// can show a scan-time evidence rollup (counts, scans, top URLs).
		findingsByDef := make(map[string][]entities.Finding)
		for _, f := range ef.Findings {
			findingsByDef[f.DefinitionID] = append(findingsByDef[f.DefinitionID], f)
		}
		seen := make(map[string]struct{})
		for _, f := range candidates {
			if _, ok := seen[f.DefinitionID]; ok {
				continue
			}
			seen[f.DefinitionID] = struct{}{}
			// Reuse cached Epic key from prior runs (persisted on Definition.EpicRef)
			// before round-tripping Jira.
			if def := defByID[f.DefinitionID]; def != nil && strings.TrimSpace(def.EpicRef) != "" {
				epicKeys[f.DefinitionID] = strings.TrimSpace(def.EpicRef)
				continue
			}
			ev := buildEpicEvidence(findingsByDef[f.DefinitionID], ef.Occurrences)
			key, err := ensureEpicForDefinition(ctx, httpClient, auth, base, defByID[f.DefinitionID], ev, opts)
			if err != nil {
				diagnostics = append(diagnostics, diagnostic("epic", f.FindingID, err))
				epicErrors++
				continue
			}
			if key == "" {
				diagnostics = append(diagnostics, publication.Diagnostic{FindingID: f.FindingID, Stage: "epic", Category: "rejected", Message: "Requested detection epic could not be resolved"})
				epicErrors++
				continue
			}
			epicKeys[f.DefinitionID] = key
		}
	}

	// Phase 1 (batch parallel): dedup check — find which findings already have issues
	type dedupResult struct {
		idx      int
		exists   bool
		issueKey string
		err      error
	}
	dedupResults := make([]dedupResult, len(candidates))
	{
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for i, f := range candidates {
			wg.Add(1)
			go func(i int, f entities.Finding) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				key, err := findExistingIssue(ctx, httpClient, auth, base, dc, f.FindingID, opts.ProjectKey)
				dedupResults[i] = dedupResult{idx: i, exists: key != "", issueKey: key, err: err}
			}(i, f)
		}
		wg.Wait()
	}

	ticketKeys := make(map[string]string)

	// Separate into to-create and skipped; record keys for already-existing issues.
	// When the dedup search itself failed we cannot know whether an issue already
	// exists, so the finding is skipped and counted as an error rather than
	// risking a duplicate ticket. The next run retries it.
	var toCreate []entities.Finding
	var skipped, dedupErrors int
	for i, r := range dedupResults {
		if r.err != nil {
			diagnostics = append(diagnostics, diagnostic("lookup", candidates[i].FindingID, r.err))
			dedupErrors++
			continue
		}
		if r.exists {
			skipped++
			ticketKeys[candidates[i].FindingID] = r.issueKey
		} else {
			toCreate = append(toCreate, candidates[i])
		}
	}

	// Phase 1.5 (batch parallel): retroactively link skipped (already-existing)
	// findings to their detection Epic when one is now available. Without this,
	// findings created before -jira-detection-epic was enabled stay orphaned
	// and the Epic shows zero child work items.
	relinked := 0
	if !opts.DryRun {
		type relinkResult struct{ ok bool }
		var (
			relinkSem = make(chan struct{}, concurrency)
			relinkWg  sync.WaitGroup
			relinkMu  sync.Mutex
		)
		for i, r := range dedupResults {
			if r.err != nil || !r.exists || r.issueKey == "" {
				continue
			}
			f := candidates[i]
			epicKey := strings.TrimSpace(epicKeys[f.DefinitionID])
			if epicKey == "" {
				continue
			}
			relinkWg.Add(1)
			go func(issueKey, epic, fid string) {
				defer relinkWg.Done()
				relinkSem <- struct{}{}
				defer func() { <-relinkSem }()
				updated, err := ensureIssueParent(ctx, httpClient, auth, base, issueKey, epic)
				if err != nil {
					relinkMu.Lock()
					diagnostics = append(diagnostics, diagnostic("parent", fid, err))
					epicErrors++
					relinkMu.Unlock()
					return
				}
				if updated {
					relinkMu.Lock()
					relinked++
					relinkMu.Unlock()
				}
			}(r.issueKey, epicKey, f.FindingID)
		}
		relinkWg.Wait()
	}

	// Phase 2 (batch parallel): create issues
	type createResult struct {
		findingID string
		issueKey  string
		err       error
	}
	createResults := make([]createResult, len(toCreate))
	{
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup
		for i, f := range toCreate {
			wg.Add(1)
			go func(i int, f entities.Finding) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				key, err := createIssue(ctx, httpClient, auth, base, dc, issueType, f, defByID[f.DefinitionID], latestOccByFind[f.FindingID], epicKeys[f.DefinitionID], opts)
				createResults[i] = createResult{findingID: f.FindingID, issueKey: key, err: err}
			}(i, f)
		}
		wg.Wait()
	}

	var created, errCount int
	for _, r := range createResults {
		if r.err != nil {
			errCount++
			diagnostics = append(diagnostics, diagnostic("create", r.findingID, r.err))
		} else {
			created++
			if r.issueKey != "" {
				ticketKeys[r.findingID] = r.issueKey
			}
		}
	}
	return Summary{Created: created, Skipped: skipped, Errors: errCount + dedupErrors + epicErrors, Diagnostics: diagnostics, TicketKeys: ticketKeys, EpicKeys: epicKeys, Relinked: relinked}, nil
}

// ensureIssueParent reads the current `parent` field on issueKey and PUTs an
// update setting it to epicKey when missing or different. Returns updated=true
// only when an actual write happened. Errors from the read step are returned;
// errors from the write step are returned with the read result lost.
func ensureIssueParent(ctx context.Context, client httpDoer, auth, base, issueKey, epicKey string) (bool, error) {
	issueKey = strings.TrimSpace(issueKey)
	epicKey = strings.TrimSpace(epicKey)
	if issueKey == "" || epicKey == "" {
		return false, nil
	}

	// 1. Read current parent. Raw variant so a 404 (issue deleted since the
	// dedup search) is data — skip quietly — rather than a logged error.
	getURL := base + "/rest/api/3/issue/" + issueKey + "?fields=parent"
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return false, err
	}
	getReq.Header.Set("Authorization", auth)
	getReq.Header.Set("Accept", "application/json")
	getResp, err := synccore.DoWithRetryRaw(client, getReq, 3)
	if err != nil {
		return false, fmt.Errorf("get parent: %w", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode == http.StatusNotFound {
		io.Copy(io.Discard, getResp.Body)
		return false, nil
	}
	if getResp.StatusCode != http.StatusOK {
		return false, jiraHTTPErr(getResp)
	}
	raw, err := io.ReadAll(io.LimitReader(getResp.Body, 64*1024))
	if err != nil {
		return false, fmt.Errorf("read parent response: %w", err)
	}
	var read struct {
		Fields struct {
			Parent *struct {
				Key string `json:"key"`
			} `json:"parent"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &read); err != nil {
		return false, fmt.Errorf("decode parent response: %w", err)
	}
	if read.Fields.Parent != nil && strings.EqualFold(strings.TrimSpace(read.Fields.Parent.Key), epicKey) {
		return false, nil // already linked
	}

	// 2. PUT the parent update.
	putBody := map[string]any{
		"fields": map[string]any{
			"parent": map[string]string{"key": epicKey},
		},
	}
	data, err := json.Marshal(putBody)
	if err != nil {
		return false, err
	}
	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/rest/api/3/issue/"+issueKey, bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	putReq.Header.Set("Authorization", auth)
	putReq.Header.Set("Content-Type", "application/json")
	putResp, err := synccore.DoWithRetryRaw(client, putReq, 3)
	if err != nil {
		return false, fmt.Errorf("put parent: %w", err)
	}
	defer putResp.Body.Close()
	if putResp.StatusCode != http.StatusNoContent && putResp.StatusCode != http.StatusOK {
		return false, jiraHTTPErr(putResp)
	}
	io.Copy(io.Discard, putResp.Body)
	return true, nil
}

// occurrenceIsNewer reports whether a should replace b as the "latest"
// occurrence for a finding. Compares ObservedAt as RFC3339 when both parse,
// otherwise falls back to string ordering; ties break on OccurrenceID so the
// choice is deterministic across runs.
func occurrenceIsNewer(a, b *entities.Occurrence) bool {
	if b == nil {
		return true
	}
	if a == nil {
		return false
	}
	ta, errA := time.Parse(time.RFC3339, strings.TrimSpace(a.ObservedAt))
	tb, errB := time.Parse(time.RFC3339, strings.TrimSpace(b.ObservedAt))
	aOK, bOK := errA == nil, errB == nil
	switch {
	case aOK && bOK:
		if !ta.Equal(tb) {
			return ta.After(tb)
		}
	case aOK && !bOK:
		return true
	case !aOK && bOK:
		return false
	default:
		if a.ObservedAt != b.ObservedAt {
			return a.ObservedAt > b.ObservedAt
		}
	}
	return a.OccurrenceID > b.OccurrenceID
}

func findingHasOptInTag(f entities.Finding, tag string) bool {
	if f.Analyst == nil {
		return false
	}
	tag = strings.ToLower(strings.TrimSpace(tag))
	if tag == "" {
		return false
	}
	for _, candidate := range f.Analyst.Tags {
		if strings.ToLower(strings.TrimSpace(candidate)) == tag {
			return true
		}
	}
	return false
}

// findExistingIssue searches for an issue with either the current or legacy
// dedup label for a finding. This keeps exports backward-compatible across
// label scheme changes and avoids duplicate issues for already-exported findings.
// Returns the issue key if found, empty string if not found.
// Uses POST /rest/api/3/search/jql on Cloud, POST /rest/api/2/search on
// Data Center — same body and response shape either way.
func findExistingIssue(ctx context.Context, client httpDoer, auth, base string, dc bool, findingID string, project ...string) (string, error) {
	labels := []string{findingLabel(findingID), legacyFindingLabel(findingID)}
	var quoted []string
	for _, label := range labels {
		quoted = append(quoted, quoteJQLString(label))
	}
	jql := fmt.Sprintf("labels in (%s)", strings.Join(quoted, ", "))
	if len(project) > 0 && strings.TrimSpace(project[0]) != "" {
		jql = "project = " + quoteJQLString(project[0]) + " AND (" + jql + ")"
	}

	body := map[string]any{
		"jql":        jql,
		"maxResults": 1,
		"fields":     []string{"id", "key"},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal search: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, searchEndpoint(base, dc), bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doRequest(client, req, 3)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode search: %w", err)
	}
	if result.Issues == nil {
		return "", fmt.Errorf("Jira search response omitted issues; refusing create")
	}
	for _, issue := range result.Issues {
		if strings.TrimSpace(issue.Key) == "" {
			return "", fmt.Errorf("Jira search response omitted issue key; refusing create")
		}
	}
	if len(result.Issues) > 0 {
		return result.Issues[0].Key, nil
	}
	return "", nil
}

// quoteJQLString wraps s in double quotes for safe embedding in a JQL clause,
// escaping backslashes and embedded quotes. Labels and IDs are generated
// internally, but a hostile entities file must not be able to alter JQL
// semantics (same hardening rationale as isValidJiraProjectKey on the
// Confluence side).
func quoteJQLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// createIssue POSTs a new Jira issue for the given Finding.
// Returns the new issue key (e.g. "KAN-42") and any error.
func createIssue(ctx context.Context, client httpDoer, auth, base string, dc bool, issueType string, f entities.Finding, def *entities.Definition, occ *entities.Occurrence, epicKey string, opts Options) (string, error) {
	labels := []string{findingLabel(f.FindingID)}
	if def != nil && def.Taxonomy != nil {
		for _, l := range def.Taxonomy.OWASPTop10 {
			labels = append(labels, sanitizeLabel(l))
		}
		for _, l := range def.Taxonomy.Tags {
			labels = append(labels, sanitizeLabel(l))
		}
	}
	for _, l := range opts.ExtraLabels {
		labels = append(labels, sanitizeLabel(l))
	}

	// Cloud's REST v3 takes an ADF document; Data Center's REST v2 takes a
	// wiki-markup string rendered from the same node tree.
	var description any = buildDescription(f, def, occ)
	if dc {
		description = renderWikiDoc(buildDescription(f, def, occ))
	}

	fields := map[string]any{
		"project":     map[string]string{"key": opts.ProjectKey},
		"summary":     issueSummary(f),
		"issuetype":   map[string]string{"name": issueType},
		"priority":    map[string]string{"name": riskToPriority(f.Risk)},
		"labels":      labels,
		"description": description,
	}
	if issueTypeID.MatchString(issueType) {
		fields["issuetype"] = map[string]string{"id": issueType}
	}
	if strings.TrimSpace(opts.Component) != "" {
		fields["components"] = []map[string]string{{"name": opts.Component}}
	}
	if ek := strings.TrimSpace(epicKey); ek != "" && !dc {
		// Next-gen / team-managed Jira Cloud projects link Epics via `parent`.
		// Classic projects use customfield_10014; that variant can be added later
		// if users hit compatibility issues. Data Center never reaches here —
		// Export disables DetectionEpic in DC mode, so epicKey stays empty.
		fields["parent"] = map[string]string{"key": ek}
	}

	// Assignee mapping (#61): translate KB analyst.owner → Jira accountId via
	// opts.UsernameMap. Skip silently when there's no owner. Warn (don't block)
	// when an owner is set but absent from the map — issue is created unassigned.
	// Data Center has no accountIds; there the mapped value is a Jira username
	// and rides in the v2 `name` field instead.
	if f.Analyst != nil {
		if owner := strings.TrimSpace(f.Analyst.Owner); owner != "" {
			if accountID := strings.TrimSpace(opts.UsernameMap[owner]); accountID != "" {
				if dc {
					fields["assignee"] = map[string]string{"name": accountID}
				} else {
					fields["assignee"] = map[string]string{"accountId": accountID}
				}
			} else {
				fmt.Fprintf(os.Stderr, "[jira] warning: no Jira accountId mapping for owner %q on finding %s; issue will be unassigned\n", owner, f.FindingID)
			}
		}
	}

	for field, value := range opts.CreateFields {
		if value == nil {
			delete(fields, field)
		} else {
			fields[field] = value
		}
	}
	body := map[string]any{"fields": fields}
	data, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal issue: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issueAPI(base, dc)+"/issue", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return createOnce(client, req, func(ctx context.Context) (string, error) {
		return findExistingIssue(ctx, client, auth, base, dc, f.FindingID, opts.ProjectKey)
	})
}

// issueSummary returns a concise Jira issue summary for a Finding.
func issueSummary(f entities.Finding) string {
	name := strings.TrimSpace(f.Name)
	if name == "" {
		name = f.FindingID
	}
	return truncateSummary(name, 255)
}

// truncateSummary trims s to at most max bytes (Jira's summary limit is 255
// characters; staying under 255 bytes is always within it), appending "..."
// and never splitting a multi-byte UTF-8 rune.
func truncateSummary(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return synccore.TruncateBytes(s, max-3) + "..."
}

// findingLabel returns the dedup label for a finding.
// Uses hyphen separator — Jira labels cannot contain colons.
func findingLabel(findingID string) string {
	return "zap-finding-" + findingID
}

// legacyFindingLabel returns the pre-migration dedup label used by older
// exporter versions. Jira lookup still searches for it to avoid duplicates.
func legacyFindingLabel(findingID string) string {
	return "zap-finding:" + findingID
}

// sanitizeLabel makes s safe for use as a Jira label:
//   - Replaces spaces, colons, slashes, and backslashes with hyphens.
//   - Strips ASCII control characters (< 0x20) and DEL (0x7F).
//   - Truncates to 255 bytes (Jira Cloud label length limit), avoiding split of multi-byte runes.
func sanitizeLabel(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7F: // control chars / DEL — strip
			continue
		case r == ' ' || r == ':' || r == '/' || r == '\\':
			b.WriteRune('-')
		default:
			b.WriteRune(r)
		}
	}
	result := b.String()
	// Truncate to 255 bytes without splitting a multi-byte rune.
	if len(result) > 255 {
		result = result[:255]
		for len(result) > 0 && result[len(result)-1]&0xC0 == 0x80 {
			result = result[:len(result)-1]
		}
	}
	return result
}
