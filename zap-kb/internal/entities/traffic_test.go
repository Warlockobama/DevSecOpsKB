package entities

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
)

func TestTrafficResponseSnippetHighRiskKeepsFullBody(t *testing.T) {
	body := strings.Repeat("stacktrace line\n", 700)
	got := trafficResponseSnippet(body, "High", 128)
	if got != body {
		t.Fatalf("high-risk response body was truncated: got %d bytes, want %d", len(got), len(body))
	}
}

func TestTrafficSnippetLimitHasMinimumFloor(t *testing.T) {
	body := strings.Repeat("a", minTrafficSnippetBytes+100)
	got := trafficRequestSnippet(body, 128)
	if len(got) != minTrafficSnippetBytes {
		t.Fatalf("traffic snippet length = %d, want minimum floor %d", len(got), minTrafficSnippetBytes)
	}
}

func TestBuildEntitiesInlineTrafficHighRiskResponseKeepsFullBody(t *testing.T) {
	body := strings.Repeat("sql error detail\n", inlineTrafficSnippetLimit/len("sql error detail\n")+20)
	ef := BuildEntitiesWithOptions([]zapclient.Alert{{
		PluginID:       "40018",
		Alert:          "SQL Injection",
		Risk:           "High",
		URL:            "https://example.test/search?q=x",
		Method:         "GET",
		ResponseHeader: "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n",
		ResponseBody:   body,
	}}, BuildOptions{GeneratedAt: "2026-01-01T00:00:00Z"})

	if len(ef.Occurrences) != 1 {
		t.Fatalf("occurrences = %d, want 1", len(ef.Occurrences))
	}
	resp := ef.Occurrences[0].Response
	if resp == nil {
		t.Fatal("expected inline response traffic")
	}
	if resp.BodySnippet != body {
		t.Fatalf("high-risk inline response was truncated: got %d bytes, want %d", len(resp.BodySnippet), len(body))
	}
	if resp.BodyBytes != len(body) {
		t.Fatalf("BodyBytes = %d, want %d", resp.BodyBytes, len(body))
	}
}

func TestBuildEntitiesInlineTrafficMediumRiskResponseStillTruncates(t *testing.T) {
	body := strings.Repeat("medium detail\n", inlineTrafficSnippetLimit/len("medium detail\n")+20)
	ef := BuildEntitiesWithOptions([]zapclient.Alert{{
		PluginID:       "10001",
		Alert:          "Medium Finding",
		Risk:           "Medium",
		URL:            "https://example.test/",
		Method:         "GET",
		ResponseHeader: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
		ResponseBody:   body,
	}}, BuildOptions{GeneratedAt: "2026-01-01T00:00:00Z"})

	resp := ef.Occurrences[0].Response
	if resp == nil {
		t.Fatal("expected inline response traffic")
	}
	if len(resp.BodySnippet) != inlineTrafficSnippetLimit {
		t.Fatalf("medium-risk inline response length = %d, want %d", len(resp.BodySnippet), inlineTrafficSnippetLimit)
	}
	if resp.BodyBytes != len(body) {
		t.Fatalf("BodyBytes = %d, want %d", resp.BodyBytes, len(body))
	}
}

func TestBuildEntitiesDerivesRequestLineWhenResponseOnly(t *testing.T) {
	ef := BuildEntitiesWithOptions([]zapclient.Alert{{
		PluginID:       "zap-legacy-ftp-surface",
		Alert:          "Legacy FTP Surface Exposed Over Web",
		Risk:           "Medium",
		URL:            "http://juice-shop.range.svc.cluster.local:3000/ftp",
		Method:         "GET",
		ResponseHeader: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
		ResponseBody:   "<html>ok</html>",
	}}, BuildOptions{GeneratedAt: "2026-01-01T00:00:00Z"})

	if len(ef.Occurrences) != 1 {
		t.Fatalf("occurrences = %d, want 1", len(ef.Occurrences))
	}
	req := ef.Occurrences[0].Request
	if req == nil {
		t.Fatal("expected derived request")
	}
	if req.DerivedFrom != RequestDerivedFromOccurrence {
		t.Fatalf("DerivedFrom = %q, want %q", req.DerivedFrom, RequestDerivedFromOccurrence)
	}
	if !strings.Contains(req.RawHeader, "GET /ftp HTTP/1.1") {
		t.Fatalf("derived raw header missing request line: %q", req.RawHeader)
	}
	if !strings.Contains(req.RawHeader, "Host: juice-shop.range.svc.cluster.local:3000") {
		t.Fatalf("derived raw header missing host: %q", req.RawHeader)
	}
	if req.BodyBytes != 0 || req.BodySnippet != "" {
		t.Fatalf("derived request should not invent a body: bytes=%d snippet=%q", req.BodyBytes, req.BodySnippet)
	}
}

func TestBuildEntitiesDoesNotDeriveRequestWithoutTraffic(t *testing.T) {
	ef := BuildEntitiesWithOptions([]zapclient.Alert{{
		PluginID: "10001",
		Alert:    "Informational Finding",
		Risk:     "Info",
		URL:      "https://example.test/path",
		Method:   "GET",
	}}, BuildOptions{GeneratedAt: "2026-01-01T00:00:00Z"})

	if len(ef.Occurrences) != 1 {
		t.Fatalf("occurrences = %d, want 1", len(ef.Occurrences))
	}
	if ef.Occurrences[0].Request != nil {
		t.Fatalf("request = %+v, want nil without captured response traffic", ef.Occurrences[0].Request)
	}
}

func TestParseRawHeadersDoesNotTreatAbsoluteRequestLineAsHeader(t *testing.T) {
	headers := parseRawHeaders("Authorization: Bearer token\r\nGET http://example.test/rest/user/whoami HTTP/1.1\r\nHost: example.test\r\n")

	for _, h := range headers {
		if h.Name == "GET http" {
			t.Fatalf("absolute-form request line was parsed as a header: %+v", headers)
		}
	}
	if got := trafficHeaderValue(headers, "authorization"); got != "Bearer token" {
		t.Fatalf("Authorization = %q, want Bearer token", got)
	}
}

func TestEnrichTrafficSelectiveSkipsMismatchedHistoryMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/JSON/core/view/message" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": map[string]string{
				"requestHeader":  "GET http://example.test/rest/user/whoami HTTP/1.1\r\nHost: example.test\r\n",
				"responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n",
				"responseBody":   `{"user":{}}`,
			},
		})
	}))
	defer server.Close()

	client, err := zapclient.NewClient(server.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ef := EntitiesFile{
		Occurrences: []Occurrence{{
			OccurrenceID: "occ-csp",
			FindingID:    "fin-csp",
			URL:          "http://example.test/",
			Method:       "GET",
			Risk:         "Medium",
			SourceID:     "3",
		}},
	}

	if err := EnrichTrafficSelective(context.Background(), client, &ef, 1, "info", 0, 1024); err != nil {
		t.Fatalf("EnrichTrafficSelective: %v", err)
	}
	if ef.Occurrences[0].Request != nil || ef.Occurrences[0].Response != nil {
		t.Fatalf("mismatched traffic should not be attached: %+v", ef.Occurrences[0])
	}
}

func TestEnrichTrafficSelectiveKeepsMatchingHistoryMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": map[string]string{
				"requestHeader":  "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n",
				"responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n",
				"responseBody":   "<html></html>",
			},
		})
	}))
	defer server.Close()

	client, err := zapclient.NewClient(server.URL, "")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ef := EntitiesFile{
		Occurrences: []Occurrence{{
			OccurrenceID: "occ-csp",
			FindingID:    "fin-csp",
			URL:          "http://example.test/",
			Method:       "GET",
			Risk:         "Medium",
			SourceID:     "3",
		}},
	}

	if err := EnrichTrafficSelective(context.Background(), client, &ef, 1, "info", 0, 1024); err != nil {
		t.Fatalf("EnrichTrafficSelective: %v", err)
	}
	if ef.Occurrences[0].Request == nil || ef.Occurrences[0].Response == nil {
		t.Fatalf("matching traffic should be attached: %+v", ef.Occurrences[0])
	}
}

func TestDropMismatchedTrafficRemovesStaleSamples(t *testing.T) {
	ef := EntitiesFile{
		Occurrences: []Occurrence{{
			OccurrenceID: "occ-csp",
			URL:          "http://example.test/",
			Method:       "GET",
			Request: &HTTPRequest{
				RawHeader: "GET http://example.test/rest/user/whoami HTTP/1.1\r\nHost: example.test\r\n",
				Headers:   parseRawHeaders("GET http://example.test/rest/user/whoami HTTP/1.1\r\nHost: example.test\r\n"),
			},
			Response: &HTTPResponse{StatusCode: 200},
		}},
	}

	if got := DropMismatchedTraffic(&ef); got != 1 {
		t.Fatalf("DropMismatchedTraffic = %d, want 1", got)
	}
	if ef.Occurrences[0].Request != nil || ef.Occurrences[0].Response != nil {
		t.Fatalf("traffic should be removed: %+v", ef.Occurrences[0])
	}
}

func TestDropMismatchedTrafficKeepsMatchingSamples(t *testing.T) {
	ef := EntitiesFile{
		Occurrences: []Occurrence{{
			OccurrenceID: "occ-csp",
			URL:          "http://example.test/",
			Method:       "GET",
			Request: &HTTPRequest{
				RawHeader: "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n",
				Headers:   parseRawHeaders("GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n"),
			},
			Response: &HTTPResponse{StatusCode: 200},
		}},
	}

	if got := DropMismatchedTraffic(&ef); got != 0 {
		t.Fatalf("DropMismatchedTraffic = %d, want 0", got)
	}
	if ef.Occurrences[0].Request == nil || ef.Occurrences[0].Response == nil {
		t.Fatalf("matching traffic should be kept: %+v", ef.Occurrences[0])
	}
}
