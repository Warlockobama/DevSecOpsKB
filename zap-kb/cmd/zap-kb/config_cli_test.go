package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCLIZapURLPrecedence(t *testing.T) {
	binary := buildTestCLI(t)

	t.Run("environment reaches intended mock", func(t *testing.T) {
		server, hits := newZAPMock(t)
		defer server.Close()
		runCLI(t, binary, []string{"ZAP_URL=" + server.URL}, "-wizard=false", "-format=flat", "-out="+filepath.Join(t.TempDir(), "alerts.json"))
		if got := hits.Load(); got != 2 {
			t.Fatalf("environment ZAP_URL reached mock %d times, want 2 paged requests", got)
		}
	})

	t.Run("explicit URL overrides environment", func(t *testing.T) {
		envServer, envHits := newZAPMock(t)
		defer envServer.Close()
		flagServer, flagHits := newZAPMock(t)
		defer flagServer.Close()
		runCLI(t, binary, []string{"ZAP_URL=" + envServer.URL}, "-wizard=false", "-format=flat", "-zap-url="+flagServer.URL, "-out="+filepath.Join(t.TempDir(), "alerts.json"))
		if got := flagHits.Load(); got != 2 {
			t.Fatalf("explicit -zap-url reached mock %d times, want 2 paged requests", got)
		}
		if got := envHits.Load(); got != 0 {
			t.Fatalf("environment mock was contacted despite explicit -zap-url: %d", got)
		}
	})

	t.Run("default reaches localhost", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:8090")
		if err != nil {
			t.Skipf("localhost default port unavailable: %v", err)
		}
		var hits atomic.Int32
		httpServer := &http.Server{Handler: zapMockHandler(t, &hits)}
		go func() { _ = httpServer.Serve(listener) }()
		defer httpServer.Close()
		runCLI(t, binary, nil, "-wizard=false", "-format=flat", "-out="+filepath.Join(t.TempDir(), "alerts.json"))
		if got := hits.Load(); got != 2 {
			t.Fatalf("default URL reached localhost mock %d times, want 2 paged requests", got)
		}
	})
}

func TestCLIConfigErrorsDoNotLeakURLValues(t *testing.T) {
	binary := buildTestCLI(t)
	cases := []struct {
		name    string
		args    []string
		markers []string
	}{
		{
			name:    "malformed URL",
			args:    []string{"-jira-url=malformed-SYNTHETIC-URL-TOKEN"},
			markers: []string{"SYNTHETIC-URL-TOKEN"},
		},
		{
			name:    "userinfo URL",
			args:    []string{"-confluence-url=https://operator:SYNTHETIC-USERINFO-SECRET@confluence.example.test/wiki?token=SYNTHETIC-QUERY-TOKEN"},
			markers: []string{"SYNTHETIC-USERINFO-SECRET", "SYNTHETIC-QUERY-TOKEN"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"atlassian", "check"}, tc.args...)
			cmd := exec.Command(binary, args...)
			cmd.Env = cleanCLIEnvironment()
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("CLI accepted invalid URL: %s", output)
			}
			text := string(output)
			for _, marker := range tc.markers {
				if strings.Contains(text, marker) {
					t.Fatalf("CLI diagnostic leaked %q: %s", marker, text)
				}
			}
		})
	}
}

func buildTestCLI(t *testing.T) string {
	t.Helper()
	name := "zap-kb"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	return binary
}

func newZAPMock(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	return httptest.NewServer(zapMockHandler(t, &hits)), &hits
}

func zapMockHandler(t *testing.T, hits *atomic.Int32) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/JSON/core/view/alerts" {
			t.Errorf("unexpected ZAP request path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("start") != "" {
			_, _ = w.Write([]byte(`{"alerts":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"alerts":[{"alert":"Configuration test","pluginId":"1","risk":"Low","url":"http://example.test"}]}`))
	})
}

func runCLI(t *testing.T, binary string, additions []string, args ...string) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = cleanCLIEnvironment(additions...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CLI failed: %v\n%s", err, output)
	}
}

func cleanCLIEnvironment(additions ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(additions))
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(entry), "ZAP_URL=") {
			env = append(env, entry)
		}
	}
	return append(env, additions...)
}
