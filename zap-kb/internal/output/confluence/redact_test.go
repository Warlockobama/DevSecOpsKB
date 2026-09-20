package confluence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestPreservedAnalystRedactionAtHTTPBoundary(t *testing.T) {
	const history = `<ac:structured-macro ac:name="info"><ac:rich-text-body><table><tbody><tr><th>Published</th><td>2026-09-12 scan-policy</td></tr><tr><th>Decision</th><td>accepted</td></tr><tr><th>Observation</th><td>PRIVATE_NOTE</td></tr><tr><th>Rationale</th><td>PRIVATE_NOTE</td></tr></tbody></table><p>PRIVATE_NOTE Useful context https://example.invalid/a?q=PRIVATE_QUERY&amp;b=PRIVATE_QUERY</p></ac:rich-text-body></ac:structured-macro>`
	body := analystLogStart + history + analystLogEnd + occNoteStart + "<p>PRIVATE_NOTE</p>" + occNoteEnd
	for _, notes := range []bool{false, true} {
		t.Run(map[bool]string{false: "preserve-notes", true: "redact-notes"}[notes], func(t *testing.T) {
			var captured string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					w.Write([]byte(`{"results":[]}`))
					return
				}
				var payload struct {
					Body struct {
						Storage struct {
							Value string `json:"value"`
						} `json:"storage"`
					} `json:"body"`
				}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Error(err)
				}
				captured = payload.Body.Storage.Value
				w.WriteHeader(201)
				w.Write([]byte(`{"id":"1"}`))
			}))
			defer server.Close()
			ctx := withOutputPolicy(context.Background(), entities.RedactOptions{Query: true, Notes: notes})
			_, _, err := upsertPage(ctx, server.Client(), "synthetic", server.URL, "TEST", "safe-title", body, "")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(captured, "PRIVATE_QUERY") {
				t.Fatal("preserved query leaked")
			}
			if notes && strings.Contains(captured, "PRIVATE_NOTE") {
				t.Fatal("preserved notes leaked")
			}
			if !notes && !strings.Contains(captured, "PRIVATE_NOTE") {
				t.Fatal("unrequested notes dropped")
			}
			safeValues := []string{"2026-09-12 scan-policy", "accepted"}
			if !notes {
				safeValues = append(safeValues, "Useful context", "ac:structured-macro")
			}
			for _, safe := range safeValues {
				if !strings.Contains(captured, safe) {
					t.Errorf("lost analyst history: %s", safe)
				}
			}
			if strings.Contains(captured, `q=<redacted>`) {
				t.Fatal("invalid unescaped HTML inserted")
			}
		})
	}
}
