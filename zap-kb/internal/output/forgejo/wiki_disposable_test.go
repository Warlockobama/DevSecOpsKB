package forgejo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestWikiDisposable creates and destroys its OWN container/volume. It never
// accepts a pre-existing destination. WIKI_DISPOSABLE=1 opts in; WIKI_IMAGE
// selects an already-downloaded image. WIKI_SIZES defaults to 100,1000,5000.
// Every publish has a 60-second whole-pass bound, configurable by WIKI_BUDGET.
// Failed/partial scale scenarios are logged, not presented as successful runs.
func TestWikiDisposable(t *testing.T) {
	if os.Getenv("WIKI_DISPOSABLE") != "1" {
		t.Skip("set WIKI_DISPOSABLE=1 for isolated Docker workload")
	}
	image := os.Getenv("WIKI_IMAGE")
	if image == "" {
		image = "codeberg.org/forgejo/forgejo:9"
	}
	budget := 60 * time.Second
	requestTimeout := 15 * time.Second
	if value := os.Getenv("WIKI_REQUEST_TIMEOUT"); value != "" {
		var err error
		requestTimeout, err = time.ParseDuration(value)
		if err != nil || requestTimeout <= 0 || requestTimeout > 2*time.Minute {
			t.Fatal("WIKI_REQUEST_TIMEOUT must be positive and at most 2m")
		}
	}
	if value := os.Getenv("WIKI_BUDGET"); value != "" {
		var err error
		budget, err = time.ParseDuration(value)
		if err != nil || budget <= 0 || budget > 5*time.Minute {
			t.Fatal("WIKI_BUDGET must be positive and at most 5m")
		}
	}
	name := "kb-wiki-perf-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	volume := name + "-data"
	t.Cleanup(func() { removeScaleResource(t, "volume", volume) })
	dockerScale(t, nil, "volume", "create", volume)
	t.Cleanup(func() { removeScaleResource(t, "container", name) })
	dockerScale(t, nil, "run", "-d", "--name", name, "--cpus=3", "--memory=1g", "-p", "127.0.0.1::3000", "-v", volume+":/data", "-e", "FORGEJO__database__DB_TYPE=sqlite3", "-e", "FORGEJO__security__INSTALL_LOCK=true", "-e", "FORGEJO__service__DISABLE_REGISTRATION=true", "-e", "FORGEJO__log__LEVEL=Error", image)
	port := strings.TrimSpace(dockerScale(t, nil, "port", name, "3000/tcp"))
	base := "http://" + port
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer readyCancel()
	for {
		req, _ := http.NewRequestWithContext(readyCtx, "GET", base+"/api/v1/version", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				t.Logf("server=%s image=%s container=%s volume=%s", body, image, name, volume)
				break
			}
		}
		select {
		case <-readyCtx.Done():
			t.Fatal("disposable server not ready within 45s")
		case <-time.After(250 * time.Millisecond):
		}
	}
	t.Logf("image_identity=%s", strings.TrimSpace(dockerScale(t, nil, "image", "inspect", image, "--format", "{{.Id}} {{json .RepoDigests}}")))
	// Random password and token remain only in subprocess response memory.
	// They are never command arguments, files, or test output.
	dockerScale(t, nil, "exec", "--user", "git", name, "forgejo", "admin", "user", "create", "--admin", "--username", "scale", "--email", "scale@example.invalid", "--random-password", "--must-change-password=false")
	tokenOutput := dockerScale(t, nil, "exec", "--user", "git", name, "forgejo", "admin", "user", "generate-access-token", "--username", "scale", "--token-name", "disposable-scale", "--scopes", "all", "--raw")
	token := strings.TrimSpace(tokenOutput)
	if fields := strings.Fields(token); len(fields) > 0 {
		token = fields[len(fields)-1]
	}
	u, _ := url.Parse(base)
	proxy := httputil.NewSingleHostReverseProxy(u)
	var mu sync.Mutex
	var proxyWG sync.WaitGroup
	statuses := map[int]int{}
	var cancelWrites context.CancelFunc
	writeResponses := 0
	metric := newScaleWiki()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyWG.Add(1)
		defer proxyWG.Done()
		started := time.Now()
		observed := &scaleStatusWriter{ResponseWriter: w, status: 200}
		endpoint := "page"
		if strings.HasSuffix(r.URL.Path, "/wiki/pages") {
			endpoint = "list"
		} else if strings.HasSuffix(r.URL.Path, "/wiki/new") {
			endpoint = "create"
		} else if !strings.Contains(r.URL.Path, "/wiki/") {
			endpoint = "repo"
		}
		// ReverseProxy can panic with ErrAbortHandler when the publisher
		// closes a fully decoded response before it has drained the body.
		// Record in a defer so those real requests are not silently omitted.
		defer func() {
			mu.Lock()
			metric.requests[r.Method+" "+endpoint] = append(metric.requests[r.Method+" "+endpoint], time.Since(started))
			statuses[observed.status]++
			if r.Method == "PATCH" && observed.status >= 200 && observed.status < 300 {
				writeResponses++
				if cancelWrites != nil && writeResponses == 10 {
					cancelWrites()
				}
			}
			mu.Unlock()
		}()
		proxy.ServeHTTP(observed, r)
	}))
	defer srv.Close()
	sizes := os.Getenv("WIKI_SIZES")
	if sizes == "" {
		sizes = "100,1000,5000"
	}
	for _, value := range strings.Split(sizes, ",") {
		size, err := strconv.Atoi(value)
		if err != nil || size < 2 || size > 5000 {
			t.Fatal("WIKI_SIZES must contain values between 2 and 5000")
		}
		t.Run(value, func(t *testing.T) {
			vault, names, files := scaleVault(t, size)
			repo := "scale-" + value
			liveScaleAPI(t, base, token, "POST", "/user/repos", map[string]any{"name": repo, "auto_init": true, "default_branch": "main", "private": true}, nil)
			// v9 API-created repositories may have an empty wiki_branch. Set
			// this on the synthetic SQLite fixture only, before any wiki writes,
			// so this experiment measures the algorithm, not that known bug.
			dockerScale(t, nil, "exec", name, "sqlite3", "/data/gitea/gitea.db", "UPDATE repository SET wiki_branch='main' WHERE lower_name='"+repo+"';")
			wikiPath := "/data/git/repositories/scale/" + repo + ".wiki.git"
			opts := WikiOptions{BaseURL: srv.URL, Token: token, Owner: "scale", Repo: repo, RequestDelay: time.Nanosecond, Concurrency: 3, Timeout: requestTimeout}
			// Fresh is a genuine API publication with no Git seed. Large fresh
			// writes are bounded even when the server cannot complete them.
			for _, scenario := range []string{"fresh", "seeded-cold", "seeded-warm", "one-page", "ten-percent", "cancellation", "recovery", "recovery-noop"} {
				if scenario == "fresh" && os.Getenv("WIKI_SKIP_FRESH") == "1" {
					for _, title := range names[:2] {
						liveScaleAPI(t, base, token, "POST", "/repos/scale/"+repo+"/wiki/new", map[string]string{"title": title, "content_base64": "c3ludGhldGlj"}, nil)
					}
					continue
				}
				if scenario == "seeded-cold" {
					// Validate the encoding used by our fast-import fixture against
					// a real server-issued path before constructing the dataset.
					var page map[string]any
					liveScaleAPI(t, base, token, "GET", "/repos/scale/"+repo+"/wiki/page/"+liveScaleSubURL(names[1]), nil, &page)
					if page["sub_url"] != liveScaleSubURL(names[1]) {
						t.Fatal("fixture encoding does not match server")
					}
					seedLiveWiki(t, name, wikiPath, names, files)
					// Restart clears process caches, not Docker VM/OS page caches.
					dockerScale(t, nil, "restart", "--time", "10", name)
					// Docker may allocate a different random host port on restart.
					base = "http://" + strings.TrimSpace(dockerScale(t, nil, "port", name, "3000/tcp"))
					u, _ = url.Parse(base)
					proxy = httputil.NewSingleHostReverseProxy(u)
					waitLiveScale(t, base)
				}
				if scenario == "one-page" {
					appendScaleContent(t, files[0], "\none page changed\n")
				}
				if scenario == "ten-percent" {
					for _, file := range files[:size/10] {
						appendScaleContent(t, file, "\nten percent changed\n")
					}
				}
				if scenario == "cancellation" {
					for _, file := range files {
						appendScaleContent(t, file, "\ninterrupted change\n")
					}
				}
				before := "0"
				if scenario != "fresh" {
					before = strings.TrimSpace(dockerScale(t, nil, "exec", "--user", "git", name, "git", "--git-dir="+wikiPath, "rev-list", "--all", "--count"))
				}
				mu.Lock()
				metric.requests = map[string][]time.Duration{}
				statuses = map[int]int{}
				cancelWrites, writeResponses = nil, 0
				mu.Unlock()
				ctx, cancel := context.WithTimeout(context.Background(), budget)
				if scenario == "cancellation" {
					mu.Lock()
					cancelWrites = cancel
					mu.Unlock()
				}
				started := time.Now()
				sum, publishErr := ExportWiki(ctx, vault, opts)
				elapsed := time.Since(started)
				cancel()
				proxyWG.Wait()
				after := strings.TrimSpace(dockerScale(t, nil, "exec", "--user", "git", name, "git", "--git-dir="+wikiPath, "rev-list", "--all", "--count"))
				beforeN, _ := strconv.Atoi(before)
				afterN, _ := strconv.Atoi(after)
				mu.Lock()
				metric.mutations = afterN - beforeN
				record := metric.metrics(size, scenario, elapsed, 0, sum)
				record["kind"], record["image"], record["history_commits"] = "disposable-forgejo", image, afterN
				record["completed"] = publishErr == nil && sum.Errors == 0
				// Endpoint latency fields describe full proxied HTTP responses in
				// this mode, including server/Git and loopback transport time.
				record["latency_scope"] = "proxy response roundtrip"
				record["budget_seconds"] = budget.Seconds()
				record["request_timeout_seconds"] = requestTimeout.Seconds()
				record["http_status_counts"] = statuses
				record["retryable_responses"] = statuses[429] + statuses[502] + statuses[503] + statuses[504]
				delete(record, "allocated_bytes") // not measured for live runs
				encoded, _ := json.Marshal(record)
				mu.Unlock()
				t.Log(string(encoded))
				t.Logf("resources=%s", strings.TrimSpace(dockerScale(t, nil, "stats", "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}} {{.BlockIO}}", name)))
				if publishErr != nil {
					t.Log("publish returned a failure; sanitized stage completion=false")
				}
				if publishErr == nil && sum.Errors == 0 && (scenario == "seeded-cold" || scenario == "seeded-warm" || scenario == "recovery-noop") && (afterN != beforeN || sum.Skipped != size) {
					t.Errorf("completed unchanged run had commits delta=%d summary=%+v", afterN-beforeN, sum)
				}
				if publishErr == nil && sum.Errors == 0 {
					// Git readback covers ALL rendered bytes. API reads for encoded
					// Home -> finding and finding -> finding links cover routing.
					verifyLiveWiki(t, name, wikiPath, names, files)
					for _, title := range names[:2] {
						var p map[string]any
						liveScaleAPI(t, base, token, "GET", "/repos/scale/"+repo+"/wiki/page/"+liveScaleSubURL(title), nil, &p)
						if p["title"] != title {
							t.Error("encoded API readback title mismatch")
						}
					}
				}
				if scenario == "seeded-warm" && os.Getenv("WIKI_UPGRADE_IMAGE") != "" {
					compareLiveSnapshot(t, name, volume, image, os.Getenv("WIKI_UPGRADE_IMAGE"), opts, vault, wikiPath, names, files)
					base = "http://" + strings.TrimSpace(dockerScale(t, nil, "port", name, "3000/tcp"))
					u, _ = url.Parse(base)
					proxy = httputil.NewSingleHostReverseProxy(u)
					waitLiveScale(t, base)
				}
				if scenario == "seeded-warm" && os.Getenv("WIKI_READS_ONLY") == "1" {
					break
				}
			}
		})
	}
}

type scaleStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *scaleStatusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *scaleStatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Compare a supported image on a copy, then restore the original snapshot into
// another disposable volume and start the baseline version. Never run an older
// binary against an upgraded database. Point-in-time volume copies are made
// while the source instance is stopped, including SQLite and repositories.
func compareLiveSnapshot(t *testing.T, original, sourceVolume, baseline, upgraded string, opts WikiOptions, vault, wikiPath string, names, files []string) {
	t.Helper()
	dockerScale(t, nil, "exec", "--user", "git", original, "forgejo", "manager", "flush-queues", "--timeout", "30s")
	dockerScale(t, nil, "stop", "--time", "10", original)
	backup := original + "-snapshot-" + strconv.Itoa(len(names))
	defer removeScaleResource(t, "volume", backup)
	dockerScale(t, nil, "volume", "create", backup)
	dockerScale(t, nil, "run", "--rm", "--entrypoint", "sh", "-v", sourceVolume+":/source:ro", "-v", backup+":/backup", baseline, "-c", "cp -a /source/. /backup/")
	defer dockerScale(t, nil, "start", original)
	for _, phase := range []string{"supported-upgrade", "baseline-restore"} {
		func() {
			volume := backup + "-" + phase
			container := volume
			defer removeScaleResource(t, "volume", volume)
			dockerScale(t, nil, "volume", "create", volume)
			dockerScale(t, nil, "run", "--rm", "--entrypoint", "sh", "-v", backup+":/source:ro", "-v", volume+":/backup", baseline, "-c", "cp -a /source/. /backup/")
			image := upgraded
			if phase == "baseline-restore" {
				image = baseline
			}
			defer removeScaleResource(t, "container", container)
			dockerScale(t, nil, "run", "-d", "--name", container, "--cpus=3", "--memory=1g", "-p", "127.0.0.1::3000", "-v", volume+":/data", image)
			base := "http://" + strings.TrimSpace(dockerScale(t, nil, "port", container, "3000/tcp"))
			waitLiveScale(t, base)
			t.Logf("comparison_image_identity=%s", strings.TrimSpace(dockerScale(t, nil, "image", "inspect", image, "--format", "{{.Id}} {{json .RepoDigests}}")))
			before := strings.TrimSpace(dockerScale(t, nil, "exec", "--user", "git", container, "git", "--git-dir="+wikiPath, "rev-parse", "HEAD"))
			verifyLiveWiki(t, container, wikiPath, names, files)
			u, _ := url.Parse(base)
			proxy := httputil.NewSingleHostReverseProxy(u)
			metric := newScaleWiki()
			var proxyWG sync.WaitGroup
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxyWG.Add(1)
				defer proxyWG.Done()
				started := time.Now()
				endpoint := "page"
				if strings.HasSuffix(r.URL.Path, "/wiki/pages") {
					endpoint = "list"
				} else if !strings.Contains(r.URL.Path, "/wiki/") {
					endpoint = "repo"
				}
				defer func() {
					metric.mu.Lock()
					metric.requests[r.Method+" "+endpoint] = append(metric.requests[r.Method+" "+endpoint], time.Since(started))
					metric.mu.Unlock()
				}()
				proxy.ServeHTTP(w, r)
			}))
			defer srv.Close()
			opts.BaseURL = srv.URL
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			started := time.Now()
			sum, err := ExportWiki(ctx, vault, opts)
			elapsed := time.Since(started)
			proxyWG.Wait()
			after := strings.TrimSpace(dockerScale(t, nil, "exec", "--user", "git", container, "git", "--git-dir="+wikiPath, "rev-parse", "HEAD"))
			metric.mu.Lock()
			record := metric.metrics(len(names), phase, elapsed, 0, sum)
			record["kind"], record["image"], record["completed"], record["head_unchanged"] = "disposable-snapshot", image, err == nil && sum.Errors == 0, before == after
			delete(record, "allocated_bytes")
			encoded, _ := json.Marshal(record)
			metric.mu.Unlock()
			t.Log(string(encoded))
			if err != nil || sum.Errors != 0 {
				t.Log("snapshot publication incomplete under three-minute budget")
				return
			}
			if before != after || sum.Skipped != len(names) {
				t.Errorf("%s did not preserve unchanged snapshot", phase)
			}
			verifyLiveWiki(t, container, wikiPath, names, files)
			for _, title := range names[:2] {
				var p map[string]any
				liveScaleAPI(t, base, opts.Token, "GET", "/repos/"+opts.Owner+"/"+opts.Repo+"/wiki/page/"+liveScaleSubURL(title), nil, &p)
				if p["title"] != title {
					t.Error("snapshot API readback mismatch")
				}
			}
			if phase == "supported-upgrade" {
				// A tiny write/readback canary is separate from the measured
				// unchanged comparison and occurs only on the upgraded copy.
				title := "Findings/upgrade-canary +%"
				path := "/repos/" + opts.Owner + "/" + opts.Repo + "/wiki/"
				var created map[string]any
				liveScaleAPI(t, base, opts.Token, "POST", path+"new", map[string]string{"title": title, "content_base64": "c3ludGhldGlj"}, &created)
				if created["sub_url"] != liveScaleSubURL(title) {
					t.Fatal("supported create path mismatch")
				}
				liveScaleAPI(t, base, opts.Token, "PATCH", path+"page/"+liveScaleSubURL(title), map[string]string{"title": title, "content_base64": "dXBkYXRlZA=="}, nil)
				var readback map[string]any
				liveScaleAPI(t, base, opts.Token, "GET", path+"page/"+liveScaleSubURL(title), nil, &readback)
				if readback["content_base64"] != "dXBkYXRlZA==" {
					t.Fatal("supported write readback mismatch")
				}
				t.Log("supported_write_canary=true scope=upgraded-disposable-copy encoded_create_patch_get=true")
			}
		}()
	}
}

func waitLiveScale(t *testing.T, base string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for {
		req, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/v1/version", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("disposable restart readiness failed")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func dockerScale(t *testing.T, input io.Reader, args ...string) string {
	t.Helper()
	limit := 60 * time.Second
	seeding := false
	for _, arg := range args {
		if arg == "fast-import" {
			limit, seeding = 180*time.Second, true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = input
	output, err := cmd.Output()
	if err != nil {
		if seeding {
			t.Logf("synthetic history setup failed: deadline=%v input_bytes_not_logged=true", ctx.Err())
		}
		t.Fatalf("disposable Docker operation %s failed (output withheld): %v", args[0], err)
	}
	return string(output)
}

// Register cleanup before creation so an operation that creates a resource and
// then fails (including docker run / readiness failure) cannot leak it. Missing
// owned resources are already clean; other cleanup failures remain test errors.
func removeScaleResource(t *testing.T, kind, name string) {
	t.Helper()
	if !strings.HasPrefix(name, "kb-wiki-perf-") || (kind != "container" && kind != "volume") {
		t.Error("refusing cleanup outside disposable benchmark namespace")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := []string{kind, "rm"}
	if kind == "container" {
		args = append(args, "-f")
	}
	args = append(args, name)
	output, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil && !strings.Contains(strings.ToLower(string(output)), "no such "+kind) {
		t.Errorf("failed to remove owned disposable %s %s (details withheld)", kind, name)
	}
}

func liveScaleAPI(t *testing.T, base, token, method, path string, data, target any) {
	t.Helper()
	body, _ := json.Marshal(data)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, method, base+"/api/v1"+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal("disposable API transport failure")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("disposable API %s failed: HTTP %d", method, resp.StatusCode)
	}
	if target != nil {
		if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
			t.Fatal("disposable API decoding failed")
		}
	}
}

func liveScaleSubURL(title string) string {
	if strings.Contains(title, "-") {
		return url.QueryEscape(title + ".-")
	}
	return url.QueryEscape(strings.ReplaceAll(title, " ", "-"))
}

func liveScaleBodies(t *testing.T, names, files []string) []string {
	t.Helper()
	pageNames := map[string]string{"INDEX.md": "Home"}
	for i := 1; i < len(names); i++ {
		pageNames["findings/"+filepath.Base(files[i])] = names[i]
	}
	bodies := make([]string, len(names))
	for i := range names {
		raw, err := readVaultMarkdown(files[i])
		if err != nil {
			t.Fatal(err)
		}
		dir := "."
		if i > 0 {
			dir = "findings"
		}
		bodies[i] = rewriteVaultLinks(raw, dir, pageNames, liveScaleSubURL)
	}
	return bodies
}

func seedLiveWiki(t *testing.T, container, wikiPath string, names, files []string) {
	t.Helper()
	bodies := liveScaleBodies(t, names, files)
	var stream strings.Builder
	// Five rounds, one page per commit, exact final rendered bytes. Each page
	// has five versions and lookup must walk up to N later commits. Fast-import
	// produces a pack; this does NOT reproduce production loose-object storage.
	for round := 0; round < 5; round++ {
		for i, title := range names {
			fmt.Fprintf(&stream, "commit refs/heads/main\ncommitter Synthetic Benchmark <scale@example.invalid> %d +0000\ndata 10\nsynthetic\n", 1700000000+round*len(names)+i)
			if round == 0 && i == 0 {
				stream.WriteString("deleteall\n")
			}
			body := bodies[i]
			if round < 4 {
				body += fmt.Sprintf("\nfixture history round %d\n", round)
			}
			gitPath := strings.ReplaceAll(liveScaleSubURL(title), "+", " ") + ".md"
			fmt.Fprintf(&stream, "M 100644 inline %s\ndata %d\n%s\n\n", strconv.Quote(gitPath), len(body), body)
		}
	}
	dockerScale(t, strings.NewReader(stream.String()), "exec", "-i", "--user", "git", container, "git", "--git-dir="+wikiPath, "fast-import", "--quiet", "--force")
	dockerScale(t, nil, "exec", "--user", "git", container, "git", "--git-dir="+wikiPath, "symbolic-ref", "HEAD", "refs/heads/main")
}

func verifyLiveWiki(t *testing.T, container, wikiPath string, names, files []string) {
	t.Helper()
	bodies := liveScaleBodies(t, names, files)
	var input strings.Builder
	for _, title := range names {
		input.WriteString("HEAD:" + strings.ReplaceAll(liveScaleSubURL(title), "+", " ") + ".md\n")
	}
	started := time.Now()
	output := dockerScale(t, strings.NewReader(input.String()), "exec", "-i", "--user", "git", container, "git", "--git-dir="+wikiPath, "cat-file", "--batch")
	t.Logf("git_bulk_read pages=%d bytes=%d duration_ms=%d scope=local-docker-exec-plus-git", len(names), len(output), time.Since(started).Milliseconds())
	reader := bytes.NewBufferString(output)
	for i, want := range bodies {
		header, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal("Git readback header missing")
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[1] != "blob" {
			t.Fatalf("Git readback missing synthetic page %d", i)
		}
		size, _ := strconv.Atoi(fields[2])
		got := make([]byte, size)
		if _, err := io.ReadFull(reader, got); err != nil {
			t.Fatal("Git readback truncated")
		}
		reader.ReadByte()
		if string(got) != want {
			t.Fatalf("Git readback content mismatch for synthetic page %d", i)
		}
	}
}
