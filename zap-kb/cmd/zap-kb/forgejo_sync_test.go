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
