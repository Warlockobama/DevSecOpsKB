package entities

import (
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
