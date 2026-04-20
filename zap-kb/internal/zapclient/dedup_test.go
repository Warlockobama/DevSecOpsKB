package zapclient

import "testing"

func TestAlertKey_StableAcrossTimestampChange(t *testing.T) {
	a := Alert{
		PluginID: "10038",
		URL:      "https://example.com/api",
		Method:   "GET",
		Evidence: "session started at 2026-04-20T15:04:05Z",
	}
	b := a
	b.Evidence = "session started at 2026-04-21T09:12:33.123+00:00"

	if AlertKey(a) != AlertKey(b) {
		t.Errorf("timestamp-only differences should produce the same key:\n a=%q => %s\n b=%q => %s",
			a.Evidence, AlertKey(a), b.Evidence, AlertKey(b))
	}
}

func TestAlertKey_StableAcrossUUIDChange(t *testing.T) {
	a := Alert{
		PluginID: "10038",
		URL:      "https://example.com/api",
		Method:   "GET",
		Evidence: "X-Request-Id: 123e4567-e89b-12d3-a456-426614174000 detected",
	}
	b := a
	b.Evidence = "X-Request-Id: 987f6543-a21b-43d2-b789-123456abcdef detected"

	if AlertKey(a) != AlertKey(b) {
		t.Errorf("UUID-only differences should produce the same key")
	}
}

func TestAlertKey_StableAcrossLongHexChange(t *testing.T) {
	a := Alert{
		PluginID: "10038",
		URL:      "https://example.com/api",
		Evidence: "nonce deadbeefcafebabe1234567890abcdef returned",
	}
	b := a
	b.Evidence = "nonce fedcba0987654321abcdef1234567890ff returned"

	if AlertKey(a) != AlertKey(b) {
		t.Errorf("long-hex-only differences should produce the same key")
	}
}

func TestAlertKey_DistinguishesMeaningfulContent(t *testing.T) {
	a := Alert{PluginID: "10038", URL: "https://example.com/a", Evidence: "CSP header missing"}
	b := Alert{PluginID: "10038", URL: "https://example.com/a", Evidence: "CSP header wildcard"}

	if AlertKey(a) == AlertKey(b) {
		t.Errorf("meaningfully different evidence should produce different keys")
	}
}

func TestAlertKey_StableAcrossLongDigitRun(t *testing.T) {
	a := Alert{PluginID: "10038", URL: "https://example.com/a", Evidence: "request 1713619200000 flagged"}
	b := Alert{PluginID: "10038", URL: "https://example.com/a", Evidence: "request 1713705600999 flagged"}

	if AlertKey(a) != AlertKey(b) {
		t.Errorf("epoch/long-digit differences should produce the same key")
	}
}

func TestNormalizeDynamic_PreservesShortDigits(t *testing.T) {
	// Short digits (like HTTP status codes, small IDs) must stay — only long
	// digit runs are treated as dynamic.
	got := normalizeDynamic("status 200 on route /api/v2")
	if got != "status 200 on route /api/v2" {
		t.Errorf("unexpected normalization of short digits: %q", got)
	}
}
