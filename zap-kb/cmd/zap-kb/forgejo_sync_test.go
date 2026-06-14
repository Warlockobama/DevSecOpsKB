package main

import (
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestForgejoRedactOptions(t *testing.T) {
	// Default (empty flag value) enables credential scrubbing.
	ro, on := forgejoRedactOptions("")
	if !on || !ro.Auth || !ro.Cookies || !ro.Headers {
		t.Fatalf("default = (%+v, %v), want auth/cookies/headers on", ro, on)
	}
	if ro.Domain || ro.Body || ro.Notes {
		t.Fatalf("default enabled extra modes: %+v", ro)
	}
	// Explicit off disables entirely.
	for _, v := range []string{"off", "none", " OFF "} {
		if _, on := forgejoRedactOptions(v); on {
			t.Errorf("forgejoRedactOptions(%q) enabled, want disabled", v)
		}
	}
	// Custom list is honored.
	ro, on = forgejoRedactOptions("domain,body")
	if !on || !ro.Domain || !ro.Body || ro.Auth {
		t.Fatalf("custom = (%+v, %v), want domain+body only", ro, on)
	}
}

func TestForgejoTicketURL(t *testing.T) {
	fn := forgejoTicketURL("https://forge.example/", "acme", "kb")
	cases := []struct {
		ref  string
		want string
	}{
		{"acme/kb#7", "https://forge.example/acme/kb/issues/7"},
		{"#12", "https://forge.example/acme/kb/issues/12"},
		{"SEC-42", ""},       // Jira key — decline so the Jira fallback applies
		{"other/repo#3", ""}, // different repo — never claim foreign refs
		{"https://forge.example/acme/kb/issues/9", "https://forge.example/acme/kb/issues/9"},
	}
	for _, c := range cases {
		if got := fn(c.ref); got != c.want {
			t.Errorf("forgejoTicketURL(%q) = %q, want %q", c.ref, got, c.want)
		}
	}
}

func TestCountOccurrencesWithTraffic(t *testing.T) {
	ent := entities.EntitiesFile{Occurrences: []entities.Occurrence{
		{OccurrenceID: "a", Request: &entities.HTTPRequest{RawHeader: "GET / HTTP/1.1"}},
		{OccurrenceID: "b", Response: &entities.HTTPResponse{RawHeader: "HTTP/1.1 200 OK"}},
		{OccurrenceID: "c"},
	}}
	if got := countOccurrencesWithTraffic(ent); got != 2 {
		t.Fatalf("countOccurrencesWithTraffic = %d, want 2", got)
	}
}

func TestRedactedCopyScrubsWithoutMutatingOriginal(t *testing.T) {
	const secret = "Bearer sup3r-s3cret-token"
	ent := entities.EntitiesFile{
		SchemaVersion: "v1",
		Findings: []entities.Finding{
			{FindingID: "fin-1", URL: "https://t/a", Risk: "High"},
		},
		Occurrences: []entities.Occurrence{{
			OccurrenceID: "occ-1",
			FindingID:    "fin-1",
			Request: &entities.HTTPRequest{
				RawHeader: "GET /a HTTP/1.1\nAuthorization: " + secret + "\nCookie: session=abc",
				Headers:   []entities.Header{{Name: "Authorization", Value: secret}},
			},
		}},
	}

	ro, on := forgejoRedactOptions("")
	if !on {
		t.Fatal("default redaction unexpectedly disabled")
	}
	cp, err := redactedCopy(ent, ro)
	if err != nil {
		t.Fatalf("redactedCopy: %v", err)
	}

	// The copy must not carry the secret anywhere the renderer could emit it.
	if req := cp.Occurrences[0].Request; req != nil {
		if strings.Contains(req.RawHeader, secret) {
			t.Errorf("copy RawHeader still contains secret")
		}
		for _, h := range req.Headers {
			if strings.Contains(h.Value, secret) {
				t.Errorf("copy header %s still contains secret", h.Name)
			}
		}
	}

	// The original (KB system of record) must be untouched.
	if req := ent.Occurrences[0].Request; !strings.Contains(req.RawHeader, secret) {
		t.Errorf("original RawHeader was mutated by redactedCopy")
	}
	if ent.Occurrences[0].Request.Headers[0].Value != secret {
		t.Errorf("original header value was mutated")
	}

	// Finding IDs must survive so ticket-ref merge keys still line up.
	if cp.Findings[0].FindingID != "fin-1" {
		t.Errorf("findingID changed in copy: %q", cp.Findings[0].FindingID)
	}
}

func TestMergeForgejoTicketRefs_ReplacesStaleSameRepoRef(t *testing.T) {
	ent := &entities.EntitiesFile{
		Findings: []entities.Finding{{
			FindingID: "F",
			Analyst:   &entities.Analyst{TicketRefs: []string{"owner/repo#5", "SEC-123"}},
		}},
	}
	changed := mergeForgejoTicketRefs(ent, map[string]string{"F": "owner/repo#3"}, "owner/repo")
	if changed != 1 {
		t.Fatalf("changed=%d, want 1", changed)
	}
	got := ent.Findings[0].Analyst.TicketRefs
	want := []string{"SEC-123", "owner/repo#3"}
	if len(got) != len(want) {
		t.Fatalf("refs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("refs = %v, want %v (foreign ref kept, stale same-repo ref replaced)", got, want)
		}
	}
}

func TestMergeForgejoTicketRefs_NoChangeWhenRefAlreadyCurrent(t *testing.T) {
	ent := &entities.EntitiesFile{
		Findings: []entities.Finding{{
			FindingID: "F",
			Analyst:   &entities.Analyst{TicketRefs: []string{"owner/repo#3"}},
		}},
	}
	changed := mergeForgejoTicketRefs(ent, map[string]string{"F": "owner/repo#3"}, "owner/repo")
	if changed != 0 {
		t.Fatalf("changed=%d, want 0", changed)
	}
	if got := ent.Findings[0].Analyst.TicketRefs; len(got) != 1 || got[0] != "owner/repo#3" {
		t.Fatalf("refs = %v, want [owner/repo#3] unchanged", got)
	}
}

// A wholesale export failure must RETURN a non-zero failure count (so the
// caller can os.Exit(1)) rather than killing the process via log.Fatalf — which
// would also abort other sinks. Pointing at an unreachable host forces Export
// to fail on its first request.
func TestRunForgejoPublish_ExportErrorReturnsFailure(t *testing.T) {
	ent := &entities.EntitiesFile{
		SchemaVersion: "v1",
		Findings:      []entities.Finding{{FindingID: "fin-1", URL: "https://t/a", Risk: "High", Occurrences: 1}},
	}
	failures := runForgejoPublish(ent, forgejoPublishOptions{
		BaseURL: "http://127.0.0.1:1",
		Token:   "t",
		Owner:   "acme",
		Repo:    "kb",
		MinRisk: "medium",
		Issues:  true,
		Redact:  "off",
	})
	if failures < 1 {
		t.Fatalf("failures=%d, want >=1 (returned, not exited)", failures)
	}
}

// Wiki-only mode (Issues=false) must not contact the issues API at all: with an
// unreachable host and the wiki step off, the publish is a clean no-op rather
// than an export failure, proving per-finding issue creation is skipped.
func TestRunForgejoPublish_WikiOnlySkipsIssues(t *testing.T) {
	ent := &entities.EntitiesFile{
		SchemaVersion: "v1",
		Findings:      []entities.Finding{{FindingID: "fin-1", URL: "https://t/a", Risk: "High", Occurrences: 1}},
	}
	failures := runForgejoPublish(ent, forgejoPublishOptions{
		BaseURL: "http://127.0.0.1:1", // unreachable — would fail if contacted
		Token:   "t",
		Owner:   "acme",
		Repo:    "kb",
		MinRisk: "medium",
		Issues:  false,
		Wiki:    false,
		Redact:  "off",
	})
	if failures != 0 {
		t.Fatalf("failures=%d, want 0 (issues skipped, wiki off — nothing should be contacted)", failures)
	}
}
