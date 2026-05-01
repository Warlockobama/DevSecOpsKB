package entities

import (
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
