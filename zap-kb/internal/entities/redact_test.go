package entities

import (
	"strings"
	"testing"
)

func makeOccurrenceWithRawHeaders(cookie, auth string) Occurrence {
	return Occurrence{
		OccurrenceID: "occ-test",
		URL:          "https://example.com/api?token=secret",
		Request: &HTTPRequest{
			Headers: []Header{
				{Name: "Cookie", Value: cookie},
				{Name: "Authorization", Value: auth},
				{Name: "Content-Type", Value: "application/json"},
			},
			RawHeader:      "GET /api?token=secret HTTP/1.1\r\nCookie: " + cookie + "\r\nAuthorization: " + auth + "\r\n",
			RawHeaderBytes: 100,
			BodySnippet:    "body data",
		},
		Response: &HTTPResponse{
			StatusCode: 200,
			Headers: []Header{
				{Name: "Set-Cookie", Value: "session=abc; HttpOnly"},
			},
			RawHeader:      "HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; HttpOnly\r\n",
			RawHeaderBytes: 60,
			BodySnippet:    "response body",
		},
	}
}

// Raw header blocks are now scrubbed line-by-line (not blanked): the targeted
// secret is removed while the rest of the evidence survives. These tests assert
// the not-contains-secret invariant per redaction category.

func TestRedactRawHeaderBlock_ScrubsSensitiveKeepsRest(t *testing.T) {
	block := "GET /search?q=secret HTTP/1.1\n" +
		"Host: target.example\n" +
		"Authorization: Bearer sekrit-token\n" +
		"Cookie: session=abc123\n" +
		"X-Api-Key: key-456\n" +
		"Accept: text/html\n"
	got := redactRawHeaderBlock(block, RedactOptions{Auth: true, Cookies: true, Headers: true})

	for _, secret := range []string{"sekrit-token", "abc123", "key-456"} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q survived:\n%s", secret, got)
		}
	}
	// Query mode is off → request line preserved verbatim.
	for _, keep := range []string{"GET /search?q=secret HTTP/1.1", "Host: target.example", "Accept: text/html"} {
		if !strings.Contains(got, keep) {
			t.Errorf("expected to keep %q:\n%s", keep, got)
		}
	}
	for _, redLine := range []string{"Authorization: <redacted>", "Cookie: <redacted>", "X-Api-Key: <redacted>"} {
		if !strings.Contains(got, redLine) {
			t.Errorf("expected redacted line %q:\n%s", redLine, got)
		}
	}
}

func TestRedactRawHeaderBlock_QueryAndDomain(t *testing.T) {
	// Query/domain redaction of a request line works when the target is an
	// absolute URL (redactURL ignores relative paths, same as the structured
	// _line rule). Host header redaction works regardless.
	block := "GET https://target.example/search?q=secret HTTP/1.1\n" +
		"Host: target.example\n" +
		"Accept: text/html\n"
	got := redactRawHeaderBlock(block, RedactOptions{Domain: true, Query: true})

	if strings.Contains(got, "secret") {
		t.Errorf("query value survived: %s", got)
	}
	if strings.Contains(got, "target.example") {
		t.Errorf("host survived: %s", got)
	}
	if !strings.Contains(got, "Accept: text/html") {
		t.Errorf("non-sensitive header dropped: %s", got)
	}
}

func TestRedactRawHeaderBlock_UnparsedLineFailsClosed(t *testing.T) {
	block := "GET /a HTTP/1.1\n" +
		"Authorization: Bearer x\n" +
		"garbage continuation\n"
	got := redactRawHeaderBlock(block, RedactOptions{Auth: true})
	if !strings.Contains(got, "<redacted: unparsed header line>") {
		t.Errorf("unparseable line not failed closed: %s", got)
	}
	if strings.Contains(got, "garbage continuation") {
		t.Errorf("unparseable line leaked: %s", got)
	}
}

func TestRedactEntities_RawHeaderScrubsCookie(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			makeOccurrenceWithRawHeaders("session=supersecret", "Bearer token123"),
		},
	}
	RedactEntities(ef, RedactOptions{Cookies: true})

	o := ef.Occurrences[0]
	if o.Request.RawHeader == "" {
		t.Fatal("RawHeader was blanked; it must be scrubbed in place")
	}
	if strings.Contains(o.Request.RawHeader, "session=supersecret") {
		t.Errorf("cookie secret survived in RawHeader: %q", o.Request.RawHeader)
	}
	if !strings.Contains(o.Request.RawHeader, "Cookie: <redacted>") {
		t.Errorf("cookie line not redacted: %q", o.Request.RawHeader)
	}
	if o.Request.RawHeaderBytes != len(o.Request.RawHeader) {
		t.Errorf("RawHeaderBytes=%d, want len(RawHeader)=%d", o.Request.RawHeaderBytes, len(o.Request.RawHeader))
	}
	if strings.Contains(o.Response.RawHeader, "session=abc") {
		t.Errorf("Set-Cookie secret survived in response RawHeader: %q", o.Response.RawHeader)
	}
	// Structured headers still redacted.
	for _, h := range o.Request.Headers {
		if h.Name == "Cookie" && h.Value != "<redacted>" {
			t.Errorf("Cookie header should be redacted in structured headers")
		}
	}
}

func TestRedactEntities_RawHeaderScrubsAuth(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			makeOccurrenceWithRawHeaders("session=abc", "Bearer supersecrettoken"),
		},
	}
	RedactEntities(ef, RedactOptions{Auth: true})

	o := ef.Occurrences[0]
	if o.Request.RawHeader == "" {
		t.Fatal("RawHeader was blanked; it must be scrubbed in place")
	}
	if strings.Contains(o.Request.RawHeader, "supersecrettoken") {
		t.Errorf("auth secret survived in RawHeader: %q", o.Request.RawHeader)
	}
	if !strings.Contains(o.Request.RawHeader, "Authorization: <redacted>") {
		t.Errorf("authorization line not redacted: %q", o.Request.RawHeader)
	}
}

func TestRedactEntities_RawHeaderScrubsHost(t *testing.T) {
	occ := Occurrence{
		OccurrenceID: "occ-host",
		Request: &HTTPRequest{
			RawHeader:      "GET /a HTTP/1.1\r\nHost: secret.host.io\r\nAccept: text/html\r\n",
			RawHeaderBytes: 100,
		},
	}
	ef := &EntitiesFile{Occurrences: []Occurrence{occ}}
	RedactEntities(ef, RedactOptions{Domain: true})

	o := ef.Occurrences[0]
	if strings.Contains(o.Request.RawHeader, "secret.host.io") {
		t.Errorf("host survived in RawHeader after domain redaction: %q", o.Request.RawHeader)
	}
	if !strings.Contains(o.Request.RawHeader, "Accept: text/html") {
		t.Errorf("non-sensitive header was dropped: %q", o.Request.RawHeader)
	}
}

func TestRedactEntities_RawHeaderPreservedWhenNoRedact(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			makeOccurrenceWithRawHeaders("session=abc", "Bearer token"),
		},
	}
	// Only body redaction — no header-touching modes
	RedactEntities(ef, RedactOptions{Body: true})

	o := ef.Occurrences[0]
	if o.Request.RawHeader == "" {
		t.Errorf("RawHeader should be preserved when only Body redaction is active")
	}
	if o.Request.RawHeaderBytes == 0 {
		t.Errorf("RawHeaderBytes should be preserved when only Body redaction is active")
	}
	// Body should be cleared
	if o.Request.BodySnippet != "" {
		t.Errorf("BodySnippet should be cleared when Body redaction is active")
	}
}

func TestRedactEntities_NilRequest(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-nil", URL: "https://example.com"},
		},
	}
	// Should not panic
	RedactEntities(ef, RedactOptions{Cookies: true, Auth: true})
}

func TestRedactEntities_BodyModeZerosAttackAndEvidence(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			{
				OccurrenceID: "occ-1",
				Attack:       "' OR 1=1--",
				Evidence:     "session=supersecret",
				Reproduce: &Reproduce{
					Curl: `curl -X POST "https://example.com/api"`,
				},
			},
		},
	}
	RedactEntities(ef, RedactOptions{Body: true})
	o := ef.Occurrences[0]
	if o.Attack != "" {
		t.Errorf("Attack should be zeroed when Body redaction is active, got: %q", o.Attack)
	}
	if o.Evidence != "" {
		t.Errorf("Evidence should be zeroed when Body redaction is active, got: %q", o.Evidence)
	}
	if o.Reproduce == nil || o.Reproduce.Curl != "" {
		t.Errorf("Reproduce.Curl should be zeroed when Body redaction is active")
	}
}

func TestRedactEntities_AuthModeRedactsCurlAuthHeaders(t *testing.T) {
	curlIn := `curl -X POST -H "Authorization: Bearer supersecret" -H "Cookie: session=abc" "https://example.com/api"`
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			{
				OccurrenceID: "occ-2",
				Reproduce: &Reproduce{
					Curl: curlIn,
				},
			},
		},
	}
	RedactEntities(ef, RedactOptions{Auth: true})
	o := ef.Occurrences[0]
	if o.Reproduce == nil {
		t.Fatal("Reproduce should not be nil")
	}
	got := o.Reproduce.Curl
	if strings.Contains(got, "supersecret") {
		t.Errorf("Reproduce.Curl should not contain Authorization value after auth redaction: %q", got)
	}
	if !strings.Contains(got, "<redacted>") {
		t.Errorf("Reproduce.Curl should contain <redacted> sentinel for Authorization: %q", got)
	}
	// Cookie inside Reproduce.Curl is also masked in auth mode (curl command context).
	if strings.Contains(got, "session=abc") {
		t.Errorf("Cookie value in Reproduce.Curl should be masked in auth mode: %q", got)
	}
	if !strings.Contains(got, "<cookie>") {
		t.Errorf("Reproduce.Curl should contain <cookie> sentinel for Cookie: %q", got)
	}
}

func TestRedactEntities_BodyModeNilReproduce(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			{OccurrenceID: "occ-3", Attack: "payload", Evidence: "leaked"},
		},
	}
	// Should not panic with nil Reproduce.
	RedactEntities(ef, RedactOptions{Body: true})
	o := ef.Occurrences[0]
	if o.Attack != "" || o.Evidence != "" {
		t.Errorf("Attack and Evidence should be zeroed")
	}
}

// TestRedactEntities_DomainRedact_NameRebuilt verifies that after domain redaction
// the Finding.Name and Occurrence.Name are rebuilt from the redacted URL so they
// no longer expose the original hostname.
func TestRedactEntities_DomainRedact_NameRebuilt(t *testing.T) {
	ef := &EntitiesFile{
		Findings: []Finding{
			{
				FindingID: "fin-1",
				URL:       "https://internal.corp.example.com/api/v1/users",
				Name:      "internal.corp.example.com — /api/v1/users",
			},
		},
		Occurrences: []Occurrence{
			{
				OccurrenceID: "occ-1",
				FindingID:    "fin-1",
				URL:          "https://internal.corp.example.com/api/v1/users?id=42",
				Name:         "internal.corp.example.com — /api/v1/users",
			},
		},
	}

	RedactEntities(ef, RedactOptions{Domain: true})

	f := ef.Findings[0]
	if strings.Contains(f.Name, "internal.corp.example.com") {
		t.Errorf("Finding.Name still contains original host after domain redaction: %q", f.Name)
	}
	if f.Name == "" {
		t.Error("Finding.Name should not be empty after domain redaction")
	}

	o := ef.Occurrences[0]
	if strings.Contains(o.Name, "internal.corp.example.com") {
		t.Errorf("Occurrence.Name still contains original host after domain redaction: %q", o.Name)
	}
	if o.Name == "" {
		t.Error("Occurrence.Name should not be empty after domain redaction")
	}
}

// TestRedactEntities_DomainRedact_URLRedacted verifies that the URL itself is
// scrubbed, and the Name is rebuilt to match the redacted URL host placeholder.
func TestRedactEntities_DomainRedact_URLRedacted(t *testing.T) {
	ef := &EntitiesFile{
		Findings: []Finding{
			{
				FindingID: "fin-2",
				URL:       "https://secret.host.io/login",
				Name:      "secret.host.io — /login",
			},
		},
		Occurrences: []Occurrence{
			{
				OccurrenceID: "occ-2",
				FindingID:    "fin-2",
				URL:          "https://secret.host.io/login",
				Name:         "secret.host.io — /login",
			},
		},
	}

	RedactEntities(ef, RedactOptions{Domain: true})

	if strings.Contains(ef.Findings[0].URL, "secret.host.io") {
		t.Errorf("Finding.URL still contains original host: %q", ef.Findings[0].URL)
	}
	if !strings.Contains(ef.Findings[0].URL, "<redacted>") {
		t.Errorf("Finding.URL should contain <redacted> placeholder: %q", ef.Findings[0].URL)
	}
	if strings.Contains(ef.Occurrences[0].URL, "secret.host.io") {
		t.Errorf("Occurrence.URL still contains original host: %q", ef.Occurrences[0].URL)
	}
}

func TestParseRedactOptionList(t *testing.T) {
	cases := []struct {
		input string
		want  RedactOptions
	}{
		{"cookies,auth", RedactOptions{Cookies: true, Auth: true}},
		{"domain query", RedactOptions{Domain: true, Query: true}},
		{"headers,body,auth", RedactOptions{Headers: true, Body: true, Auth: true}},
		{"", RedactOptions{}},
		{"COOKIES,AUTH", RedactOptions{Cookies: true, Auth: true}},
		{"notes", RedactOptions{Notes: true}},
		{"note", RedactOptions{Notes: true}},
	}
	for _, tc := range cases {
		got := ParseRedactOptionList(tc.input)
		if got != tc.want {
			t.Errorf("ParseRedactOptionList(%q) = %+v, want %+v", tc.input, got, tc.want)
		}
	}
}

func TestRedactEntities_NotesModeScrubsAnalystAndReproduceSteps(t *testing.T) {
	ef := &EntitiesFile{
		Findings: []Finding{{
			FindingID: "fin-1",
			Analyst: &Analyst{
				Notes:     "creds: admin/hunter2",
				Rationale: "confirmed via curl -u admin:hunter2",
				Status:    "triaged",
				Owner:     "alice",
			},
		}},
		Occurrences: []Occurrence{{
			OccurrenceID: "occ-1",
			Analyst: &Analyst{
				Notes:     "token=eyJ...",
				Rationale: "decision rationale",
			},
			Reproduce: &Reproduce{
				Curl:  "curl https://example.com",
				Steps: []string{"1. login with admin/hunter2", "2. POST /api"},
			},
		}},
	}

	RedactEntities(ef, RedactOptions{Notes: true})

	af := ef.Findings[0].Analyst
	if af.Notes != "" || af.Rationale != "" {
		t.Errorf("finding analyst free text not cleared: Notes=%q Rationale=%q", af.Notes, af.Rationale)
	}
	if af.Status != "triaged" || af.Owner != "alice" {
		t.Errorf("finding analyst structural fields should be preserved: %+v", af)
	}

	ao := ef.Occurrences[0].Analyst
	if ao.Notes != "" || ao.Rationale != "" {
		t.Errorf("occurrence analyst free text not cleared: Notes=%q Rationale=%q", ao.Notes, ao.Rationale)
	}
	rep := ef.Occurrences[0].Reproduce
	if len(rep.Steps) != 0 {
		t.Errorf("reproduce steps not cleared: %v", rep.Steps)
	}
	if rep.Curl != "curl https://example.com" {
		t.Errorf("reproduce curl should be untouched by notes mode: %q", rep.Curl)
	}
}

func TestRedactEntities_NotesMode_NilAnalystAndReproduce(t *testing.T) {
	ef := &EntitiesFile{
		Findings:    []Finding{{FindingID: "fin-1"}},
		Occurrences: []Occurrence{{OccurrenceID: "occ-1"}},
	}
	RedactEntities(ef, RedactOptions{Notes: true}) // must not panic
}
