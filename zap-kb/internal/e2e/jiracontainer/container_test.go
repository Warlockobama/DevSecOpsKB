//go:build container

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const syntheticToken = "synthetic-container-token"

func TestPublisherImageJiraContract(t *testing.T) {
	if os.Getenv("CONTAINER_JIRA") != "1" {
		t.Skip("set CONTAINER_JIRA=1 to run the isolated publisher image contract")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	module := moduleRoot(t)
	revision := strings.TrimSpace(run(t, ctx, module, "git", "rev-parse", "HEAD"))
	prefix := "zap-kb-jira-" + randomSuffix(t)
	publisherImage := prefix + ":publisher"
	stubImage := prefix + ":stub"
	network := prefix

	runDocker(t, ctx, module, "build", "-f", filepath.Join(module, "deploy", "Dockerfile"),
		"--build-arg", "VERSION=container-contract", "--build-arg", "REVISION="+revision,
		"--build-arg", "BUILD_TIME=unknown", "-t", publisherImage, module)
	runDocker(t, ctx, module, "build", "-t", stubImage, filepath.Join(module, "internal", "e2e", "jiracontainer"))
	assertImageIdentity(t, ctx, module, publisherImage, revision)
	runDocker(t, ctx, module, "network", "create", "--internal", network)
	t.Cleanup(func() { runDockerBestEffort(context.Background(), module, "network", "rm", network) })

	for _, tc := range []struct {
		name    string
		mode    string
		baseURL string
		wantOK  bool
	}{
		{name: "cloud-create-readback", mode: "accept", baseURL: "http://jira.atlassian.net:8080", wantOK: true},
		{name: "cloud-rejected-create", mode: "reject", baseURL: "http://jira.atlassian.net:8080", wantOK: false},
		{name: "cloud-gateway-auto", mode: "accept", baseURL: "http://api.atlassian.com:8080/ex/jira/mock-cloud", wantOK: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runCase(t, ctx, module, prefix, network, publisherImage, stubImage, tc.name, tc.mode, tc.baseURL, tc.wantOK)
		})
	}
}

func runCase(t *testing.T, ctx context.Context, module, prefix, network, publisherImage, stubImage, name, mode, baseURL string, wantOK bool) {
	t.Helper()
	stub := prefix + "-" + name
	runDocker(t, ctx, module, "run", "-d", "--name", stub, "--network", network,
		"--network-alias", "jira.atlassian.net", "--network-alias", "api.atlassian.com",
		"-e", "JIRA_STUB_MODE="+mode, stubImage)
	t.Cleanup(func() { runDockerBestEffort(context.Background(), module, "rm", "-f", stub) })
	waitForStub(t, ctx, module, network, publisherImage)

	work := t.TempDir()
	if err := os.Chmod(work, 0o777); err != nil {
		t.Fatalf("make output directory writable by the non-root publisher: %v", err)
	}
	fixture := filepath.Join(module, "testdata", "alerts_smoke.json")
	outputMount := "type=bind,source=" + work + ",target=/output"
	fixtureMount := "type=bind,source=" + fixture + ",target=/fixtures/alerts.json,readonly"
	args := []string{
		"run", "--rm", "--network", network, "--mount", outputMount, "--mount", fixtureMount,
		"-e", "JIRA_URL=" + baseURL,
		"-e", "JIRA_PROJECT=TEST",
		"-e", "JIRA_USER=synthetic@example.invalid",
		"-e", "JIRA_API_TOKEN=" + syntheticToken,
		publisherImage,
		"-wizard=false", "-in", "/fixtures/alerts.json", "-format", "entities", "-out", "/output/entities.json",
		"-run-out", "/output/run.json", "-publish-summary-out", "/output/summary.json",
		"-scan-label", "container-jira-contract", "-generated-at", "2026-09-12T00:00:00Z",
	}
	_, exitCode := runDockerExit(ctx, module, args...)
	// The publisher intentionally writes private 0600 files as uid 65532. Give
	// ownership of this disposable bind mount back to the test runner so Linux
	// CI can inspect and remove the artifacts without changing the image user.
	if runtime.GOOS != "windows" {
		owner := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
		restore := []string{"run", "--rm", "--network", "none", "--user", "0:0", "--mount", outputMount,
			"--entrypoint", "/bin/chown", publisherImage, "-R", owner, "/output"}
		restored := false
		t.Cleanup(func() {
			if !restored {
				runDockerBestEffort(context.Background(), module, restore...)
			}
		})
		runDocker(t, ctx, module, restore...)
		restored = true
	}
	if wantOK && exitCode != 0 {
		t.Fatalf("publisher exit=%d, want 0", exitCode)
	}
	if !wantOK && exitCode == 0 {
		t.Fatalf("publisher exit=0 for synthetic Jira HTTP 400; expected a truthful nonzero result")
	}
	for _, file := range []string{"entities.json", "run.json", "summary.json"} {
		data, err := os.ReadFile(filepath.Join(work, file))
		if err != nil {
			t.Fatalf("required saved artifact %s: %v", file, err)
		}
		if strings.Contains(string(data), syntheticToken) || strings.Contains(string(data), "synthetic@example.invalid") {
			t.Fatalf("saved artifact %s contains a synthetic credential", file)
		}
	}
	requests := runDocker(t, ctx, module, "logs", stub)
	if !strings.Contains(requests, `"path":"`+expectedPath(baseURL, "/rest/api/3/search/jql")+`"`) ||
		!strings.Contains(requests, `"path":"`+expectedPath(baseURL, "/rest/api/3/issue")+`"`) {
		t.Fatalf("expected Cloud v3 search and create requests; received only sanitized request paths")
	}
	if wantOK && !strings.Contains(requests, `"path":"`+expectedPath(baseURL, "/rest/api/3/issue/TEST-1")+`"`) {
		t.Fatal("successful create did not perform the expected Jira readback")
	}
}

func expectedPath(baseURL, path string) string {
	if strings.Contains(baseURL, "/ex/jira/mock-cloud") {
		return "/ex/jira/mock-cloud" + path
	}
	return path
}

func assertImageIdentity(t *testing.T, ctx context.Context, dir, image, revision string) {
	t.Helper()
	label := strings.TrimSpace(runDocker(t, ctx, dir, "image", "inspect", image, "--format", "{{index .Config.Labels \"org.opencontainers.image.revision\"}}"))
	if label != revision {
		t.Fatalf("OCI revision label=%q, want %q", label, revision)
	}
	version := strings.TrimSpace(runDocker(t, ctx, dir, "run", "--rm", image, "-version"))
	if !strings.Contains(version, "revision="+revision) {
		t.Fatalf("embedded binary version does not report reviewed revision")
	}
}

func waitForStub(t *testing.T, ctx context.Context, dir, network, clientImage string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_, code := runDockerExit(ctx, dir, "run", "--rm", "--network", network,
			"--entrypoint", "/usr/bin/curl", clientImage, "-fsS", "http://jira.atlassian.net:8080/ready")
		if code == 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("synthetic Jira fixture did not become ready")
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

func runDocker(t *testing.T, ctx context.Context, dir string, args ...string) string {
	t.Helper()
	out, code := runDockerExit(ctx, dir, args...)
	if code != 0 {
		t.Fatalf("docker command failed (exit %d)", code)
	}
	return out
}

func runDockerExit(ctx context.Context, dir string, args ...string) (string, int) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = dir
	cmd.Env = scrubbedEnv()
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(out), exitErr.ExitCode()
	}
	return string(out), -1
}

func runDockerBestEffort(ctx context.Context, dir string, args ...string) {
	_, _ = runDockerExit(ctx, dir, args...)
}

func run(t *testing.T, ctx context.Context, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = scrubbedEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("required local build metadata unavailable")
	}
	return string(out)
}

func scrubbedEnv() []string {
	blocked := []string{"ZAP_", "JIRA_", "CONFLUENCE_", "FORGEJO_"}
	clean := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		blockedName := false
		for _, prefix := range blocked {
			if strings.HasPrefix(upper, prefix) {
				blockedName = true
				break
			}
		}
		if !blockedName {
			clean = append(clean, entry)
		}
	}
	return clean
}
