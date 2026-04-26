package confluence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// --- findingStateSig ---

func TestFindingStateSig_NilFinding(t *testing.T) {
	sig := findingStateSig(nil, "")
	if sig != "" {
		t.Errorf("expected empty sig for nil finding, got %q", sig)
	}
}

func TestFindingStateSig_Basic(t *testing.T) {
	f := &entities.Finding{
		FindingID:   "fin-abc",
		Risk:        "Medium",
		Occurrences: 3,
		LastSeen:    "2026-04-03T18:44:31Z",
	}
	sig := findingStateSig(f, "To Do")
	want := "occ=3|risk=Medium|lastSeen=2026-04-03T18:44:31Z|jira=To Do|status=|owner="
	if sig != want {
		t.Errorf("got %q, want %q", sig, want)
	}
}

func TestFindingStateSig_EmptyJira(t *testing.T) {
	f := &entities.Finding{
		FindingID:   "fin-abc",
		Risk:        "High",
		Occurrences: 1,
	}
	sig := findingStateSig(f, "")
	if !strings.HasPrefix(sig, "occ=1|risk=High|lastSeen=") {
		t.Errorf("unexpected sig: %q", sig)
	}
	if !strings.Contains(sig, "|jira=|") {
		t.Errorf("expected empty jira segment in sig: %q", sig)
	}
}

func TestFindingStateSig_ChangesWhenStateChanges(t *testing.T) {
	f := &entities.Finding{FindingID: "fin-1", Risk: "Low", Occurrences: 1}
	sig1 := findingStateSig(f, "")
	f.Occurrences = 2
	sig2 := findingStateSig(f, "")
	if sig1 == sig2 {
		t.Error("sig should differ when occurrence count changes")
	}
}

// --- extractAnalystLog ---

func TestExtractAnalystLog_Present(t *testing.T) {
	body := `<p>something</p>` +
		analystLogStart +
		`<p>log entry</p>` +
		analystLogEnd +
		`<p>after</p>`
	got := extractAnalystLog(body)
	want := `<p>log entry</p>`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractAnalystLog_Missing(t *testing.T) {
	body := `<p>no markers here</p>`
	got := extractAnalystLog(body)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestExtractAnalystLog_EmptyContent(t *testing.T) {
	body := analystLogStart + analystLogEnd
	got := extractAnalystLog(body)
	if got != "" {
		t.Errorf("expected empty string between empty markers, got %q", got)
	}
}

func TestExtractAnalystLog_MultipleEntries(t *testing.T) {
	entries := `<entry1/><entry2/>`
	body := analystLogStart + entries + analystLogEnd
	got := extractAnalystLog(body)
	if got != entries {
		t.Errorf("got %q, want %q", got, entries)
	}
}

// --- extractStateSig ---

func TestExtractStateSig_Present(t *testing.T) {
	sig := "occ=1|risk=Medium|lastSeen=2026-04-09T00:00:00Z|jira=To Do"
	body := `<p>stuff</p><span class="kb-state-sig" style="display:none">` + sig + `</span><p>more</p>`
	got := extractStateSig(body)
	if got != sig {
		t.Errorf("got %q, want %q", got, sig)
	}
}

func TestExtractStateSig_Missing(t *testing.T) {
	body := `<p>no sig here</p>`
	got := extractStateSig(body)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestExtractStateSig_Empty(t *testing.T) {
	body := `<span class="kb-state-sig" style="display:none"></span>`
	got := extractStateSig(body)
	if got != "" {
		t.Errorf("expected empty for empty sig, got %q", got)
	}
}

// --- demoteFirstInfoEntry ---

func TestDemoteFirstInfoEntry_HasInfo(t *testing.T) {
	log := `<ac:structured-macro ac:name="info"><ac:rich-text-body>entry1</ac:rich-text-body></ac:structured-macro>` +
		`<ac:structured-macro ac:name="expand"><ac:rich-text-body>entry2</ac:rich-text-body></ac:structured-macro>`
	got := demoteFirstInfoEntry(log)
	if strings.Contains(got, `ac:name="info"`) {
		t.Error("demote should have replaced all ac:name=\"info\" with expand, but info still found")
	}
	// Should have exactly two "expand" occurrences now
	count := strings.Count(got, `ac:name="expand"`)
	if count != 2 {
		t.Errorf("expected 2 expand macros after demotion, got %d", count)
	}
}

func TestDemoteFirstInfoEntry_NoInfo(t *testing.T) {
	log := `<ac:structured-macro ac:name="expand"><ac:rich-text-body>entry</ac:rich-text-body></ac:structured-macro>`
	got := demoteFirstInfoEntry(log)
	if got != log {
		t.Error("log without info should be unchanged")
	}
}

func TestDemoteFirstInfoEntry_Empty(t *testing.T) {
	got := demoteFirstInfoEntry("")
	if got != "" {
		t.Error("empty log should remain empty")
	}
}

func TestDemoteFirstInfoEntry_OnlyDemotesFirst(t *testing.T) {
	// If somehow two info macros exist, only the first should be demoted.
	log := `<ac:structured-macro ac:name="info">A</ac:structured-macro>` +
		`<ac:structured-macro ac:name="info">B</ac:structured-macro>`
	got := demoteFirstInfoEntry(log)
	infoCount := strings.Count(got, `ac:name="info"`)
	expandCount := strings.Count(got, `ac:name="expand"`)
	if infoCount != 1 || expandCount != 1 {
		t.Errorf("expected 1 info and 1 expand after single demotion, got info=%d expand=%d", infoCount, expandCount)
	}
}

// --- buildLogEntry ---

func TestBuildLogEntry_NilFinding(t *testing.T) {
	got := buildLogEntry(nil, nil, "", nil, time.Now().UTC().Format(time.RFC3339), true)
	if got != "" {
		t.Errorf("expected empty for nil finding, got %q", got)
	}
}

func TestBuildLogEntry_MostRecentUsesInfoMacro(t *testing.T) {
	f := &entities.Finding{
		FindingID:   "fin-abc",
		Risk:        "Medium",
		Occurrences: 2,
		LastSeen:    "2026-04-09T00:00:00Z",
	}
	got := buildLogEntry(f, nil, "", nil, "2026-04-09T10:00:00Z", true)
	if !strings.Contains(got, `ac:name="info"`) {
		t.Error("most-recent entry should use info macro")
	}
	if strings.Contains(got, `ac:name="expand"`) {
		t.Error("most-recent entry should not use expand macro")
	}
}

func TestBuildLogEntry_OlderUsesExpandMacro(t *testing.T) {
	f := &entities.Finding{
		FindingID:   "fin-abc",
		Risk:        "Medium",
		Occurrences: 2,
	}
	got := buildLogEntry(f, nil, "", nil, "2026-04-09T10:00:00Z", false)
	if strings.Contains(got, `ac:name="info"`) {
		t.Error("older entry should not use info macro")
	}
	if !strings.Contains(got, `ac:name="expand"`) {
		t.Error("older entry should use expand macro")
	}
}

func TestBuildLogEntry_ContainsRequiredFields(t *testing.T) {
	f := &entities.Finding{
		FindingID:   "fin-abc",
		Risk:        "High",
		Occurrences: 5,
		LastSeen:    "2026-04-09T12:00:00Z",
		Analyst: &entities.Analyst{
			TicketRefs: []string{"KAN-42"},
		},
	}
	got := buildLogEntry(f, nil, "https://jira.example.com", map[string]string{"KAN-42": "In Progress"}, "2026-04-09T10:00:00Z", true)

	checks := []struct {
		name string
		want string
	}{
		{"Published field", "Published"},
		{"Risk field", "Risk"},
		{"Occurrences field", "Occurrences"},
		{"Last seen field", "Last seen"},
		{"Jira case field", "Jira case"},
		{"Observation prompt", "(enter observation)"},
		{"Decision prompt", "open | triaged | fp | accepted | fixed"},
		{"Rationale prompt", "(why this decision)"},
		{"Next steps prompt", "(what to do next)"},
	}
	for _, c := range checks {
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: expected %q in output", c.name, c.want)
		}
	}
}

func TestBuildLogEntry_ScanLabels(t *testing.T) {
	f := &entities.Finding{FindingID: "fin-abc", Risk: "Low", Occurrences: 1}
	ei := &entityIndex{findingScans: map[string][]string{"fin-abc": {"scan-2026-04-01", "scan-2026-04-08"}}}
	got := buildLogEntry(f, ei, "", nil, time.Now().UTC().Format(time.RFC3339), true)
	if !strings.Contains(got, "scan-2026-04-01") {
		t.Error("expected scan labels in log entry")
	}
}

func TestBuildLogEntry_LastSeenDateFormatted(t *testing.T) {
	f := &entities.Finding{
		FindingID:   "fin-abc",
		Risk:        "Low",
		Occurrences: 1,
		LastSeen:    "2026-04-09T15:30:00Z",
	}
	got := buildLogEntry(f, nil, "", nil, "2026-04-09T10:00:00Z", true)
	// Should render as YYYY-MM-DD not RFC3339
	if !strings.Contains(got, "2026-04-09") {
		t.Error("expected short date in last seen field")
	}
}

// --- buildAnalystLogSection ---

func TestBuildAnalystLogSection_ContainsMarkers(t *testing.T) {
	got := buildAnalystLogSection("", "")
	if !strings.Contains(got, analystLogStart) {
		t.Error("expected analyst log start marker")
	}
	if !strings.Contains(got, analystLogEnd) {
		t.Error("expected analyst log end marker")
	}
}

func TestBuildAnalystLogSection_ContainsEditHint(t *testing.T) {
	// Sig is now stored via page properties API, not in the body.
	// The body should contain an edit hint for analysts instead.
	got := buildAnalystLogSection("", "")
	if !strings.Contains(got, "Edit") {
		t.Error("expected edit hint in analyst log section")
	}
	if strings.Contains(got, `class="kb-state-sig"`) {
		t.Error("sig span must NOT be in the page body (stored via page property API)")
	}
}

func TestBuildAnalystLogSection_NewEntryPrepended(t *testing.T) {
	newEntry := `<ac:structured-macro ac:name="info">NEW</ac:structured-macro>`
	existing := `<ac:structured-macro ac:name="info">OLD</ac:structured-macro>`
	got := buildAnalystLogSection(newEntry, existing)

	// Extract content between markers
	content := extractAnalystLog(got)
	if !strings.HasPrefix(content, newEntry) {
		t.Error("new entry should appear before existing log")
	}
	// OLD entry should be demoted (info → expand)
	if strings.Contains(content, `ac:name="info">OLD`) {
		t.Error("old entry should have been demoted from info to expand")
	}
}

func TestBuildAnalystLogSection_NoNewEntryPreservesExisting(t *testing.T) {
	existing := `<ac:structured-macro ac:name="info">EXISTING</ac:structured-macro>`
	got := buildAnalystLogSection("", existing)
	content := extractAnalystLog(got)
	if content != existing {
		t.Errorf("without new entry, existing log should be preserved unchanged; got %q", content)
	}
}

// --- buildAnalystHistorySection ---

func TestBuildAnalystHistorySection_Empty(t *testing.T) {
	got := buildAnalystHistorySection(nil, "")
	if got != "" {
		t.Error("expected empty string for no summaries")
	}
}

func TestBuildAnalystHistorySection_RendersRows(t *testing.T) {
	summaries := []logSummary{
		{
			FindingID:   "fin-00868f1a",
			FindingURL:  "https://confluence.example.com/spaces/KB/pages/123",
			PublishedAt: "2026-04-09T10:00:00Z",
			Risk:        "Medium",
			JiraCase:    "KAN-189",
			JiraStatus:  "To Do",
		},
	}
	got := buildAnalystHistorySection(summaries, "https://jira.example.com")
	checks := []string{
		"Analyst History",
		"fin-00868f1a",
		"2026-04-09", // short date
		"KAN-189",
	}
	for _, c := range checks {
		if !strings.Contains(got, c) {
			t.Errorf("expected %q in analyst history section", c)
		}
	}
}

// --- fetchPageStorageBody ---

func TestFetchPageStorageBody_Success(t *testing.T) {
	wantBody := "<p>Hello from storage</p>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/rest/api/content/") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"body": map[string]any{
				"storage": map[string]string{
					"value": wantBody,
				},
			},
		})
	}))
	defer srv.Close()

	client := &http.Client{}
	got, err := fetchPageStorageBody(context.Background(), client, "Basic dXNlcjp0b2tlbg==", srv.URL, "42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantBody {
		t.Errorf("got %q, want %q", got, wantBody)
	}
}

func TestFetchPageStorageBody_EmptyPageID(t *testing.T) {
	client := &http.Client{}
	_, err := fetchPageStorageBody(context.Background(), client, "auth", "http://example.com", "")
	if err == nil {
		t.Error("expected error for empty page ID")
	}
}

func TestFetchPageStorageBody_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := &http.Client{}
	_, err := fetchPageStorageBody(context.Background(), client, "Basic dXNlcjp0b2tlbg==", srv.URL, "999")
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

// --- round-trip integration: sig detection triggers new entry ---

func TestAnalystLog_StateChangeTriggersNewEntry(t *testing.T) {
	f := &entities.Finding{
		FindingID:   "fin-abc",
		Risk:        "Medium",
		Occurrences: 1,
		LastSeen:    "2026-04-01T00:00:00Z",
	}

	// First publish — no existing page.
	// Sig is now stored via page property API; simulate it as a plain string here.
	sig1 := findingStateSig(f, "")
	entry1 := buildLogEntry(f, nil, "", nil, "2026-04-01T10:00:00Z", true)
	section1 := buildAnalystLogSection(entry1, "")

	// Section must NOT contain the sig span (stored externally now).
	if strings.Contains(section1, `class="kb-state-sig"`) {
		t.Error("sig span must not appear in page body")
	}

	// Second publish — state unchanged. Simulate: stored sig == current sig.
	existingLog := extractAnalystLog(section1)
	storedSig := sig1 // simulates what was saved to page property
	currentSig := findingStateSig(f, "")

	if currentSig != storedSig {
		t.Fatal("sigs should match when state is unchanged")
	}
	// No new entry when sig matches.
	section2 := buildAnalystLogSection("", existingLog)
	log2 := extractAnalystLog(section2)
	if log2 != existingLog {
		t.Error("existing log should be preserved when no new entry")
	}

	// Third publish — occurrences increased. New entry should appear.
	f.Occurrences = 2
	f.LastSeen = "2026-04-09T00:00:00Z"
	newSig := findingStateSig(f, "")
	if newSig == storedSig {
		t.Fatal("sig should differ after state change")
	}
	entry3 := buildLogEntry(f, nil, "", nil, "2026-04-09T10:00:00Z", true)
	section3 := buildAnalystLogSection(entry3, existingLog)
	log3 := extractAnalystLog(section3)

	// New entry should appear first.
	if !strings.HasPrefix(log3, entry3) {
		t.Error("new entry should be at the front of the log")
	}
	// Previous entry should be demoted from info → expand in the section.
	if strings.Count(log3, `ac:name="info"`) > 1 {
		t.Error("only the newest entry should use info macro")
	}
}

// --- occurrence note preserve ---

func TestExtractOccurrenceNote_Absent(t *testing.T) {
	if got := extractOccurrenceNote("<p>body with no markers</p>"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestExtractOccurrenceNote_RoundTrip(t *testing.T) {
	section := buildOccurrenceNoteSection("<p>my analyst note</p>")
	if !strings.Contains(section, "<h2>Scan Observation</h2>") {
		t.Errorf("expected 'Scan Observation' heading in built section, got: %s", section)
	}
	if !strings.Contains(section, occNoteStart) || !strings.Contains(section, occNoteEnd) {
		t.Errorf("expected markers in built section, got: %s", section)
	}
	// Embed the section in a larger body and re-extract.
	body := "<p>prefix</p>" + section + "<p>suffix</p>"
	got := strings.TrimSpace(extractOccurrenceNote(body))
	if got != "<p>my analyst note</p>" {
		t.Errorf("round-trip mismatch: got %q", got)
	}
}

func TestBuildOccurrenceNoteSection_SeedsPlaceholderWhenEmpty(t *testing.T) {
	section := buildOccurrenceNoteSection("")
	if !strings.Contains(section, "scan-specific observations") {
		t.Errorf("expected scan-specific placeholder seed, got: %s", section)
	}
}

func TestBuildFindingVerdictSection_RendersAllFields(t *testing.T) {
	f := &entities.Finding{
		FindingID: "fin-1",
		Analyst: &entities.Analyst{
			Status:    "accepted",
			Owner:     "alice",
			Notes:     "low risk in this env",
			Rationale: "compensating control: WAF",
		},
	}
	section := buildFindingVerdictSection(f)
	for _, want := range []string{
		"<h2>Finding Verdict</h2>",
		"alice",
		"low risk in this env",
		"compensating control: WAF",
		`ac:name="status"`, // status macro
	} {
		if !strings.Contains(section, want) {
			t.Errorf("expected %q in verdict section; got:\n%s", want, section)
		}
	}
}

func TestBuildFindingVerdictSection_EmptyWhenNoAnalystData(t *testing.T) {
	cases := []struct {
		name string
		f    *entities.Finding
	}{
		{"nil finding", nil},
		{"nil analyst", &entities.Finding{FindingID: "x"}},
		{"empty analyst", &entities.Finding{FindingID: "x", Analyst: &entities.Analyst{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildFindingVerdictSection(tc.f); got != "" {
				t.Errorf("expected empty section; got: %s", got)
			}
		})
	}
}

// --- parseStateSig ---

func TestParseStateSig_RoundTripsFindingStateSig(t *testing.T) {
	f := &entities.Finding{
		Occurrences: 5,
		Risk:        "Medium",
		LastSeen:    "2026-04-07T00:00:00Z",
		Analyst:     &entities.Analyst{Status: "triaged", Owner: "alice"},
	}
	sig := findingStateSig(f, "In Review")
	got := parseStateSig(sig)
	want := map[string]string{
		"occ":      "5",
		"risk":     "Medium",
		"lastSeen": "2026-04-07T00:00:00Z",
		"jira":     "In Review",
		"status":   "triaged",
		"owner":    "alice",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("parseStateSig[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseStateSig_EmptyReturnsEmptyMap(t *testing.T) {
	got := parseStateSig("")
	if got == nil || len(got) != 0 {
		t.Errorf("parseStateSig(\"\") = %v, want non-nil empty map", got)
	}
}

func TestParseStateSig_TolerantOfLegacySig(t *testing.T) {
	// Legacy sigs lack status/owner — parse should succeed with those
	// fields missing, and buildChangelogSection should treat them as "—".
	got := parseStateSig("occ=3|risk=Low|lastSeen=2026-04-01T00:00:00Z|jira=")
	if got["occ"] != "3" || got["risk"] != "Low" || got["status"] != "" || got["owner"] != "" {
		t.Errorf("unexpected parse: %+v", got)
	}
}

// --- buildChangelogSection ---

func TestBuildChangelogSection_EmptyWhenPrevMissing(t *testing.T) {
	curr := parseStateSig("occ=1|risk=High|status=open|owner=|jira=|lastSeen=")
	if got := buildChangelogSection(nil, curr, "2026-04-20T00:00:00Z"); got != "" {
		t.Errorf("first publish should produce no changelog, got: %s", got)
	}
}

func TestBuildChangelogSection_EmptyWhenUnchanged(t *testing.T) {
	sig := parseStateSig("occ=1|risk=High|status=open|owner=|jira=|lastSeen=")
	if got := buildChangelogSection(sig, sig, "2026-04-20T00:00:00Z"); got != "" {
		t.Errorf("unchanged state should produce no changelog, got: %s", got)
	}
}

func TestBuildChangelogSection_StatusAndOwnerDiff(t *testing.T) {
	prev := parseStateSig("occ=3|risk=Medium|status=open|owner=|jira=To Do|lastSeen=2026-04-01T00:00:00Z")
	curr := parseStateSig("occ=3|risk=Medium|status=triaged|owner=alice|jira=In Review|lastSeen=2026-04-01T00:00:00Z")
	got := buildChangelogSection(prev, curr, "2026-04-20T00:00:00Z")
	for _, want := range []string{
		"Changes since last publish",
		"<td>Status</td><td>open</td><td>triaged</td>",
		"<td>Owner</td><td>\u2014</td><td>alice</td>",
		"<td>Jira status</td><td>To Do</td><td>In Review</td>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("changelog missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Occurrences") {
		t.Errorf("unchanged occurrence count should not appear in changelog:\n%s", got)
	}
}

func TestBuildChangelogSection_NewOccurrenceDelta(t *testing.T) {
	prev := parseStateSig("occ=3|risk=Medium|status=open|owner=|jira=|lastSeen=")
	curr := parseStateSig("occ=5|risk=Medium|status=open|owner=|jira=|lastSeen=")
	got := buildChangelogSection(prev, curr, "")
	if !strings.Contains(got, "+2 new occurrences (now 5)") {
		t.Errorf("expected signed occurrence delta row, got:\n%s", got)
	}
}

func TestBuildChangelogSection_OccurrenceRegression(t *testing.T) {
	prev := parseStateSig("occ=7|risk=Medium|status=open|owner=|jira=|lastSeen=")
	curr := parseStateSig("occ=4|risk=Medium|status=open|owner=|jira=|lastSeen=")
	got := buildChangelogSection(prev, curr, "")
	if !strings.Contains(got, "-3 fewer occurrences (now 4)") {
		t.Errorf("expected negative delta row, got:\n%s", got)
	}
}
