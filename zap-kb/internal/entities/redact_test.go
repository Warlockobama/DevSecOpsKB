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

func TestRedactEntities_RawHeaderZeroedOnCookieRedact(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			makeOccurrenceWithRawHeaders("session=supersecret", "Bearer token123"),
		},
	}
	RedactEntities(ef, RedactOptions{Cookies: true})

	o := ef.Occurrences[0]
	if o.Request.RawHeader != "" {
		t.Errorf("RawHeader should be zeroed when Cookies redaction is active, got: %q", o.Request.RawHeader)
	}
	if o.Request.RawHeaderBytes != 0 {
		t.Errorf("RawHeaderBytes should be 0 when Cookies redaction is active, got: %d", o.Request.RawHeaderBytes)
	}
	if o.Response.RawHeader != "" {
		t.Errorf("Response RawHeader should be zeroed, got: %q", o.Response.RawHeader)
	}
	// Structured headers still redacted
	for _, h := range o.Request.Headers {
		if h.Name == "Cookie" && h.Value != "<redacted>" {
			t.Errorf("Cookie header should be redacted in structured headers")
		}
	}
}

func TestRedactEntities_RawHeaderZeroedOnAuthRedact(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			makeOccurrenceWithRawHeaders("session=abc", "Bearer supersecrettoken"),
		},
	}
	RedactEntities(ef, RedactOptions{Auth: true})

	o := ef.Occurrences[0]
	if o.Request.RawHeader != "" {
		t.Errorf("RawHeader should be zeroed when Auth redaction is active")
	}
	if o.Request.RawHeaderBytes != 0 {
		t.Errorf("RawHeaderBytes should be 0 when Auth redaction is active")
	}
}

func TestRedactEntities_RawHeaderZeroedOnDomainRedact(t *testing.T) {
	ef := &EntitiesFile{
		Occurrences: []Occurrence{
			makeOccurrenceWithRawHeaders("x", "y"),
		},
	}
	RedactEntities(ef, RedactOptions{Domain: true})

	o := ef.Occurrences[0]
	if o.Request.RawHeader != "" {
		t.Errorf("RawHeader should be zeroed when Domain redaction is active (Host header leaks)")
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
	}
	for _, tc := range cases {
		got := ParseRedactOptionList(tc.input)
		if got != tc.want {
			t.Errorf("ParseRedactOptionList(%q) = %+v, want %+v", tc.input, got, tc.want)
		}
	}
}
