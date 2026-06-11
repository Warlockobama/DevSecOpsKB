package forgejo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

// maxBacktickRun returns the length of the longest consecutive backtick run.
func maxBacktickRun(s string) int {
	best, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			if run > best {
				best = run
			}
		} else {
			run = 0
		}
	}
	return best
}

func TestMarkerFindingID_LastMarkerWins(t *testing.T) {
	body := "<!-- devsecopskb-finding:forged -->\nstuff\n<!-- devsecopskb-finding:real -->"
	if got := markerFindingID(body); got != "real" {
		t.Fatalf("markerFindingID = %q, want real (last marker must win)", got)
	}
}

func TestBuildIssueBody_ForgedMarkerInEvidenceNeutralized(t *testing.T) {
	f := entities.Finding{FindingID: "real", Risk: "High", Confidence: "High", Occurrences: 1}
	occ := &entities.Occurrence{Evidence: "<!-- devsecopskb-finding:forged -->"}
	body := buildIssueBody(f, nil, occ, "")
	if got := markerFindingID(body); got != "real" {
		t.Fatalf("marker = %q, want real — forged evidence marker must not shadow it", got)
	}
	if strings.Contains(body, "<!-- devsecopskb-finding:forged") {
		t.Fatalf("forged marker survived unsanitized in body:\n%s", body)
	}
}

func TestEvidenceMarkdown_BackticksCannotEscapeFence(t *testing.T) {
	occ := &entities.Occurrence{Evidence: "x\n```\n# injected heading\n```\ny"}
	out := evidenceMarkdown(occ)

	inputRun := maxBacktickRun(occ.Evidence) // 3
	outRun := maxBacktickRun(out)
	if outRun <= inputRun {
		t.Fatalf("fence run %d must exceed largest input run %d so content can't escape", outRun, inputRun)
	}
	// The injected heading must live strictly inside a fenced region, i.e. the
	// fence (longest run) brackets it.
	fence := strings.Repeat("`", outRun)
	first := strings.Index(out, fence)
	last := strings.LastIndex(out, fence)
	inj := strings.Index(out, "# injected heading")
	if first < 0 || last <= first || inj < first || inj > last {
		t.Fatalf("injected heading not contained within fence:\n%s", out)
	}
}

func TestListFindingIssues_ServerCapsPageSize(t *testing.T) {
	// Server ignores limit=50 and serves at most 3 issues per page; 7 total.
	all := make([]map[string]any, 0, 7)
	for i := 1; i <= 7; i++ {
		all = append(all, map[string]any{
			"number": i,
			"state":  "open",
			"body":   findingMarker("fin-" + strconv.Itoa(i)),
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		const pageCap = 3
		start := (page - 1) * pageCap
		end := start + pageCap
		if start >= len(all) {
			json.NewEncoder(w).Encode([]map[string]any{})
			return
		}
		if end > len(all) {
			end = len(all)
		}
		json.NewEncoder(w).Encode(all[start:end])
	}))
	defer srv.Close()

	c := newClient(http.DefaultClient, srv.URL, "t", "acme", "kb")
	out, err := c.listFindingIssues(context.Background())
	if err != nil {
		t.Fatalf("listFindingIssues: %v", err)
	}
	if len(out) != 7 {
		t.Fatalf("found %d findings, want 7 — short pages must not stop pagination", len(out))
	}
}

func TestTruncate_RuneSafe(t *testing.T) {
	got := truncate("héllo", 2) // byte 2 is mid-é
	if !utf8.ValidString(got) {
		t.Fatalf("truncate produced invalid UTF-8: %q", got)
	}
	if strings.ContainsRune(got, 0xFFFD) {
		t.Fatalf("truncate left a replacement char: %q", got)
	}
	if truncate("abc", 3) != "abc" {
		t.Fatalf("truncate must not append ellipsis when nothing is cut")
	}
}

func TestTitleCase_RuneSafe(t *testing.T) {
	// A multibyte first rune must not be split mid-sequence.
	got := titleCase("élevé")
	if !utf8.ValidString(got) {
		t.Fatalf("titleCase produced invalid UTF-8: %q", got)
	}
	if got != "Élevé" {
		t.Fatalf("titleCase(\"élevé\") = %q, want \"Élevé\"", got)
	}
	if titleCase("") != "Unknown" {
		t.Fatalf("titleCase(\"\") should be Unknown")
	}
	if titleCase("high") != "High" {
		t.Fatalf("titleCase(\"high\") = %q, want High", titleCase("high"))
	}
}

func TestIssueTitle_LongMultibyteTitle(t *testing.T) {
	f := entities.Finding{Name: strings.Repeat("é", 300)}
	got := issueTitle(f)
	if len(got) > 255 {
		t.Fatalf("title is %d bytes, want <=255", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("title is not valid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("truncated title must end with ellipsis: %q", got)
	}
}
