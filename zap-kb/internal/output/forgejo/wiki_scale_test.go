package forgejo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This is an HTTP contract and client-work benchmark, not a Forgejo/Git
// throughput benchmark. Opt in with WIKI_SCALE=1; each workload is disposable.
// No credentials, production endpoint or retained remote data are used.
func TestWikiScale(t *testing.T) {
	if os.Getenv("WIKI_SCALE") != "1" {
		t.Skip("set WIKI_SCALE=1 to run the bounded synthetic scale workload")
	}
	for _, size := range []int{100, 1000, 5000} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			vault, names, files := scaleVault(t, size)
			remote := newScaleWiki()
			srv := httptest.NewServer(remote)
			defer srv.Close()
			opts := WikiOptions{BaseURL: srv.URL, Token: "synthetic", Owner: "scale", Repo: "disposable", Concurrency: 3, RequestDelay: time.Nanosecond, Timeout: 5 * time.Second}
			for _, scenario := range []string{"fresh", "unchanged", "one-page", "ten-percent", "cancellation", "recovery", "recovery-noop"} {
				switch scenario {
				case "one-page":
					appendScaleContent(t, files[0], "\none-page change\n")
				case "ten-percent":
					for _, file := range files[:size/10] {
						appendScaleContent(t, file, "\nten-percent change\n")
					}
				case "cancellation":
					for _, file := range files {
						appendScaleContent(t, file, "\ninterrupted change\n")
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				remote.reset()
				if scenario == "cancellation" {
					remote.mu.Lock()
					remote.cancelAfter = 10
					remote.cancel = cancel
					remote.mu.Unlock()
				}
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				started := time.Now()
				sum, err := ExportWiki(ctx, vault, opts)
				elapsed := time.Since(started)
				cancel()
				runtime.ReadMemStats(&after)
				remote.mu.Lock()
				metrics := remote.metrics(size, scenario, elapsed, after.TotalAlloc-before.TotalAlloc, sum)
				mutations := remote.mutations
				remote.mu.Unlock()
				data, _ := json.Marshal(metrics)
				t.Log(string(data))
				if scenario == "cancellation" {
					if err == nil && sum.Errors == 0 {
						t.Fatal("canceled publish reported success")
					}
					if mutations < 10 || mutations > 13 {
						t.Fatalf("cancellation mutations=%d, want 10 plus at most in-flight workers", mutations)
					}
					continue
				}
				if err != nil || sum.Errors != 0 {
					t.Fatalf("%s: summary=%+v err=%v", scenario, sum, err)
				}
				if scenario == "unchanged" || scenario == "recovery-noop" {
					if mutations != 0 || sum.Skipped != size {
						t.Fatalf("%s: mutations=%d summary=%+v", scenario, mutations, sum)
					}
				}
				if scenario == "one-page" && mutations != 1 || scenario == "ten-percent" && mutations != size/10 {
					t.Fatalf("%s: unexpected mutations=%d", scenario, mutations)
				}
				remote.verify(t, names, files)
			}
		})
	}
}

type scaleWikiPage struct {
	Title   string `json:"title"`
	SubURL  string `json:"sub_url"`
	Content string `json:"-"`
}

type scaleWiki struct {
	mu          sync.Mutex
	pages       map[string]scaleWikiPage
	requests    map[string][]time.Duration
	mutations   int
	cancelAfter int
	cancel      context.CancelFunc
	// Optional handler hook supports deterministic concurrent-state tests.
	beforeRead func(*scaleWiki, string)
}

func newScaleWiki() *scaleWiki {
	return &scaleWiki{pages: map[string]scaleWikiPage{}, requests: map[string][]time.Duration{}}
}

func (s *scaleWiki) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = map[string][]time.Duration{}
	s.mutations, s.cancelAfter, s.cancel = 0, 0, nil
}

func (s *scaleWiki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	endpoint := "unexpected"
	s.mu.Lock()
	defer func() {
		s.requests[r.Method+" "+endpoint] = append(s.requests[r.Method+" "+endpoint], time.Since(start))
		s.mu.Unlock()
	}()
	const prefix = "/api/v1/repos/scale/disposable"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == prefix:
		endpoint = "repo"
		json.NewEncoder(w).Encode(map[string]bool{"has_wiki": true})
	case r.Method == http.MethodGet && r.URL.Path == prefix+"/wiki/pages":
		endpoint = "list"
		names := make([]string, 0, len(s.pages))
		for name := range s.pages {
			names = append(names, name)
		}
		sort.Strings(names)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		start := (page - 1) * 50
		batch := []scaleWikiPage{}
		for i := start; i < start+50 && i < len(names); i++ {
			batch = append(batch, s.pages[names[i]])
		}
		json.NewEncoder(w).Encode(batch)
	case r.Method == http.MethodPost && r.URL.Path == prefix+"/wiki/new":
		endpoint = "create"
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		if _, exists := s.pages[body["title"]]; exists {
			w.WriteHeader(409)
			return
		}
		content, err := base64.StdEncoding.DecodeString(body["content_base64"])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		p := scaleWikiPage{Title: body["title"], SubURL: scaleSubURL(body["title"]), Content: string(content)}
		s.pages[p.Title] = p
		s.mutated()
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(p)
	case strings.HasPrefix(r.URL.Path, prefix+"/wiki/page/"):
		endpoint = "page"
		sub := strings.TrimPrefix(r.URL.EscapedPath(), prefix+"/wiki/page/")
		if r.Method == http.MethodGet && s.beforeRead != nil {
			s.beforeRead(s, sub)
		}
		var p scaleWikiPage
		for _, item := range s.pages {
			if item.SubURL == sub {
				p = item
				break
			}
		}
		if p.Title == "" {
			w.WriteHeader(404)
			return
		}
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]string{"title": p.Title, "sub_url": p.SubURL, "content_base64": base64.StdEncoding.EncodeToString([]byte(p.Content))})
			return
		}
		if r.Method != http.MethodPatch {
			w.WriteHeader(405)
			return
		}
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		content, err := base64.StdEncoding.DecodeString(body["content_base64"])
		if err != nil {
			w.WriteHeader(400)
			return
		}
		p.Content = string(content)
		s.pages[p.Title] = p
		s.mutated()
		json.NewEncoder(w).Encode(p)
	default:
		w.WriteHeader(500)
	}
}

func (s *scaleWiki) mutated() {
	s.mutations++
	if s.cancel != nil && s.mutations == s.cancelAfter {
		s.cancel()
	}
}

func scaleSubURL(name string) string {
	if strings.Contains(name, "/") {
		return url.PathEscape(name) + ".-"
	}
	return url.PathEscape(name)
}

func scaleVault(t *testing.T, size int) (string, []string, []string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "findings"), 0o755); err != nil {
		t.Fatal(err)
	}
	names, files := []string{"Home"}, []string{filepath.Join(root, "INDEX.md")}
	for i := 1; i < size; i++ {
		name := fmt.Sprintf("fin-%05d + %%", i)
		names = append(names, "Findings/"+name)
		files = append(files, filepath.Join(root, "findings", name+".md"))
	}
	for i, file := range files {
		link := "INDEX.md"
		if i == 0 {
			link = "findings/" + filepath.Base(files[1])
		} else if i < size-1 {
			link = filepath.Base(files[i+1])
		} else {
			link = "../INDEX.md"
		}
		body := fmt.Sprintf("---\nfixture: synthetic\n---\n# %s\n\n[[%s#details|next page]]\n\n%s\n", names[i], link, strings.Repeat("Synthetic evidence only. ", 170))
		if err := os.WriteFile(file, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root, names, files
}

func appendScaleContent(t *testing.T, file, value string) {
	t.Helper()
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(value)
	closeErr := f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func (s *scaleWiki) verify(t *testing.T, names, files []string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	pageNames := map[string]string{"INDEX.md": "Home"}
	for i := 1; i < len(names); i++ {
		pageNames["findings/"+filepath.Base(files[i])] = names[i]
	}
	for i, name := range names {
		raw, err := readVaultMarkdown(files[i])
		if err != nil {
			t.Fatal(err)
		}
		dir := "."
		if i > 0 {
			dir = "findings"
		}
		want := rewriteVaultLinks(raw, dir, pageNames, scaleSubURL)
		if s.pages[name].Content != want {
			t.Fatalf("remote content/link mismatch for synthetic page %d", i)
		}
		if !strings.Contains(s.pages[name].Content, "]("+scaleSubURL(names[(i+1)%len(names)])+"#details)") {
			t.Fatalf("encoded next-page link missing from synthetic page %d", i)
		}
	}
}

func (s *scaleWiki) metrics(size int, scenario string, elapsed time.Duration, alloc uint64, summary WikiSummary) map[string]any {
	endpoints := map[string]any{}
	for endpoint, latencies := range s.requests {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		var total time.Duration
		for _, d := range latencies {
			total += d
		}
		endpoints[endpoint] = map[string]any{"requests": len(latencies), "handler_total_ms": float64(total.Microseconds()) / 1000, "handler_p50_ms": float64(latencies[(len(latencies)-1)/2].Microseconds()) / 1000, "handler_p95_ms": float64(latencies[(len(latencies)-1)*95/100].Microseconds()) / 1000}
	}
	return map[string]any{"kind": "synthetic-http", "runtime": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "pages": size, "scenario": scenario, "duration_ms": float64(elapsed.Microseconds()) / 1000, "allocated_bytes": alloc, "mutations": s.mutations, "summary": summary, "endpoints": endpoints}
}
