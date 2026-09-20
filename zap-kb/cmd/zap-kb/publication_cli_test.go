package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

func TestCLIPublicationFailureMatrix(t *testing.T) {
	binary := buildTestCLI(t)
	for _, tc := range []struct {
		name                             string
		lookup, create, conf, pull, link int
		full                             bool
		recoverCreate, cancel            bool
		wantFailure                      bool
	}{
		{name: "all success", create: 201, conf: 200},
		{name: "pull permissions", create: 201, conf: 200, pull: 403, wantFailure: true},
		{name: "evidence link rejection", create: 201, conf: 200, link: 403, full: true, wantFailure: true},
		{name: "Jira required field rejected", create: 400, conf: 200, wantFailure: true},
		{name: "Confluence failed Jira succeeds", create: 201, conf: 403, wantFailure: true},
		{name: "all destinations failed", create: 400, conf: 403, wantFailure: true},
		{name: "lookup authentication", lookup: 401, conf: 200, wantFailure: true},
		{name: "lookup permission", lookup: 403, conf: 200, wantFailure: true},
		{name: "lookup missing endpoint", lookup: 404, conf: 200, wantFailure: true},
		{name: "lookup exhausted retries", lookup: 503, conf: 200, wantFailure: true},
		{name: "create rate limited", create: 429, conf: 200, wantFailure: true},
		{name: "ambiguous create reconciled", create: 500, conf: 200, recoverCreate: true},
		{name: "ambiguous create unresolved", create: 500, conf: 200, wantFailure: true},
		{name: "canceled lookup", conf: 200, cancel: true, wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var creates, confCalls, linkCalls atomic.Int32
			jiraServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/search/jql"):
					if tc.cancel {
						select {
						case <-r.Context().Done():
						case <-time.After(time.Second):
						}
						return
					}
					if tc.lookup > 0 {
						w.WriteHeader(tc.lookup)
						io.WriteString(w, `{"errorMessages":["REMOTE_PRIVATE_MARKER"]}`)
						return
					}
					if tc.recoverCreate && creates.Load() > 0 {
						io.WriteString(w, `{"issues":[{"key":"SEC-1"}]}`)
					} else {
						io.WriteString(w, `{"issues":[]}`)
					}
				case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/issue"):
					creates.Add(1)
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(tc.create)
					if tc.create == 201 {
						io.WriteString(w, `{"key":"SEC-1"}`)
					} else {
						io.WriteString(w, `{"errors":{"customfield_10042":"REMOTE_PRIVATE_MARKER is required"}}`)
					}
				case strings.HasSuffix(r.URL.Path, "/remotelink"):
					if r.Method == "GET" {
						io.WriteString(w, `[]`)
					} else {
						linkCalls.Add(1)
						w.WriteHeader(tc.link)
						io.WriteString(w, `{"message":"REMOTE_PRIVATE_MARKER"}`)
					}
				case r.Method == "GET" && strings.Contains(r.URL.Path, "/issue/SEC-1"):
					if tc.pull > 0 {
						w.WriteHeader(tc.pull)
						return
					}
					io.WriteString(w, `{"key":"SEC-1","fields":{"status":{"name":"In Progress"},"assignee":{"displayName":"REMOTE_PRIVATE_MARKER@example.invalid"}}}`)
				default:
					t.Errorf("unexpected Jira request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer jiraServer.Close()
			confServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				confCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if tc.conf != 200 {
					w.WriteHeader(tc.conf)
					io.WriteString(w, `{"message":"REMOTE_PRIVATE_MARKER"}`)
					return
				}
				if r.Method == "GET" {
					io.WriteString(w, `{"results":[]}`)
				} else {
					io.WriteString(w, `{"id":"1","version":{"number":1}}`)
				}
			}))
			defer confServer.Close()
			dir := t.TempDir()
			input, out, run, vault, archive := filepath.Join(dir, "input.json"), filepath.Join(dir, "out.json"), filepath.Join(dir, "run.json"), filepath.Join(dir, "vault"), filepath.Join(dir, "bundle.zip")
			fixture := policyFixture()
			if err := runartifact.Write(input, fixture); err != nil {
				t.Fatal(err)
			}
			args := []string{"-wizard=false", "-run-in=" + input, "-format=entities", "-out=" + out, "-run-out=" + run, "-obsidian-dir=" + vault, "-zip-out=" + archive, "-redact=" + allOutputModes, "-include-mitre=false", "-include-cvss=false", "-jira-url=" + jiraServer.URL, "-jira-deployment=cloud", "-jira-project=SEC", "-confluence-url=" + confServer.URL, "-confluence-space=KB"}
			if tc.full {
				args = append(args, "-confluence-full")
			}
			if tc.cancel {
				args = append(args, "-jira-timeout=50ms")
			}
			cmd := exec.Command(binary, args...)
			cmd.Env = cleanCLIEnvironment("JIRA_API_TOKEN=synthetic", "JIRA_USER=synthetic@example.invalid", "CONFLUENCE_TOKEN=synthetic", "CONFLUENCE_USER=synthetic@example.invalid")
			logs, err := cmd.CombinedOutput()
			if (err != nil) != tc.wantFailure {
				t.Fatalf("exit mismatch: %v\n%s", err, logs)
			}
			if confCalls.Load() == 0 {
				t.Fatal("Jira failure prevented unrelated Confluence work")
			}
			if tc.lookup > 0 || tc.cancel {
				if creates.Load() != 0 {
					t.Fatal("created after failed lookup")
				}
			}
			if tc.create == 500 && creates.Load() != 1 {
				t.Fatal("ambiguous create replayed")
			}
			a, err := runartifact.Read(run)
			if err != nil {
				t.Fatal(err)
			}
			if a.Publication == nil || (a.Publication.Err() != nil) != tc.wantFailure {
				t.Fatalf("run did not retain required outcomes: %+v", a.Publication)
			}
			if tc.full && linkCalls.Load() == 0 {
				t.Fatalf("link rejection fixture did not reach remote-link POST: %s", logs)
			}
			if tc.full && !stageRecorded(a.Publication, "jira", "evidence_links") {
				t.Fatal("missing evidence-link outcome")
			}
			if !stageRecorded(a.Publication, "jira", "pull") || !stageRecorded(a.Publication, "confluence", "publish") {
				t.Fatal("missing stage outcomes")
			}
			b, err := os.ReadFile(run + ".publication.json")
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "REMOTE_PRIVATE_MARKER") || strings.Contains(string(logs), "REMOTE_PRIVATE_MARKER") {
				t.Fatal("remote details leaked")
			}
			if tc.create == 400 && (!strings.Contains(string(b), "customfield_10042") || !strings.Contains(string(logs), "finding-policy")) {
				t.Fatal("missing actionable finding/field diagnostics")
			}
			zr, err := zip.OpenReader(archive)
			if err != nil {
				t.Fatal(err)
			}
			defer zr.Close()
			foundSummary := false
			for _, f := range zr.File {
				if strings.HasSuffix(f.Name, "publication.json") {
					foundSummary = true
				}
			}
			if !foundSummary {
				t.Fatal("ZIP omitted publication results")
			}
		})
	}
}

func TestCLIArtifactFailuresRetainOtherSaves(t *testing.T) {
	binary := buildTestCLI(t)
	for _, bad := range []string{"zip", "summary", "run"} {
		t.Run(bad, func(t *testing.T) {
			dir := t.TempDir()
			input, out, run, summary, archive := filepath.Join(dir, "input.json"), filepath.Join(dir, "out.json"), filepath.Join(dir, "run.json"), filepath.Join(dir, "summary.json"), filepath.Join(dir, "bundle.zip")
			if err := runartifact.Write(input, policyFixture()); err != nil {
				t.Fatal(err)
			}
			blocked := filepath.Join(dir, "blocked")
			if err := os.Mkdir(blocked, 0700); err != nil {
				t.Fatal(err)
			}
			switch bad {
			case "zip":
				archive = blocked
			case "summary":
				summary = blocked
			case "run":
				run = blocked
			}
			cmd := exec.Command(binary, "-wizard=false", "-run-in="+input, "-format=entities", "-out="+out, "-run-out="+run, "-publish-summary-out="+summary, "-zip-out="+archive, "-redact="+allOutputModes, "-include-mitre=false", "-include-cvss=false")
			cmd.Env = cleanCLIEnvironment()
			logs, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("artifact failure exited successfully: %s", logs)
			}
			if bad != "run" {
				a, err := runartifact.Read(run)
				if err != nil {
					t.Fatal(err)
				}
				if a.Publication == nil || a.Publication.Err() == nil {
					t.Fatal("run artifact omitted final save failure")
				}
			}
			if bad != "zip" {
				z, err := zip.OpenReader(archive)
				if err != nil {
					t.Fatal(err)
				}
				z.Close()
			}
			if bad != "summary" {
				b, err := os.ReadFile(summary)
				if err != nil {
					t.Fatal(err)
				}
				var s atlassianPublishSummary
				if json.Unmarshal(b, &s) != nil || s.Publication.Err() == nil {
					t.Fatal("summary omitted artifact failure")
				}
			}
		})
	}
}

func TestRequiredZeroCounterErrorAndCleanup(t *testing.T) {
	var r publication.Result
	recordPublication(&r, "forgejo", "wiki", 0, 0, 0, fmt.Errorf("REMOTE_PRIVATE_MARKER"), false)
	if r.Err() == nil || r.Stages[0].Status != publication.Failed {
		t.Fatal("zero-counter package error lost")
	}
	cleanup := false
	code := executeCLI(func() { defer func() { cleanup = true }(); exitCLI(1) })
	if code != 1 || !cleanup {
		t.Fatal("exit bypassed deferred cleanup")
	}
	r = publication.Result{}
	recordPublication(&r, "jira", "publish", 0, 0, 0, context.Canceled, false)
	if !strings.Contains(r.Stages[0].Diagnostics[0].Message, "may have committed") {
		t.Fatal("cancellation omitted remote-write uncertainty")
	}
}

func TestCLIWikiZeroCounterFailureAndMetrics(t *testing.T) {
	binary := buildTestCLI(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/wiki/pages") {
			w.WriteHeader(500)
			io.WriteString(w, `{"message":"REMOTE_PRIVATE_MARKER"}`)
			return
		}
		io.WriteString(w, `{"has_wiki":true}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	input, run := filepath.Join(dir, "input.json"), filepath.Join(dir, "run.json")
	if err := runartifact.Write(input, policyFixture()); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-wizard=false", "-run-in="+input, "-format=entities", "-out="+filepath.Join(dir, "out.json"), "-run-out="+run, "-obsidian-dir="+filepath.Join(dir, "vault"), "-forgejo-url="+srv.URL, "-forgejo-owner=owner", "-forgejo-repo=repo", "-forgejo-issues=false", "-forgejo-wiki", "-include-mitre=false", "-include-cvss=false")
	cmd.Env = cleanCLIEnvironment("FORGEJO_TOKEN=synthetic")
	logs, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("wiki discovery failure exited successfully: %s", logs)
	}
	a, err := runartifact.Read(run)
	if err != nil {
		t.Fatal(err)
	}
	if a.Publication == nil {
		t.Fatal("missing outcomes")
	}
	for _, stage := range a.Publication.Stages {
		if stage.Destination == "forgejo" && stage.Stage == "wiki" {
			if stage.Status != publication.Failed || stage.Failed == 0 || stage.Requests < 2 || len(stage.Phases) < 2 {
				t.Fatalf("zero-counter error or phase metrics lost: %+v", stage)
			}
			return
		}
	}
	t.Fatal("missing wiki stage")
}

func TestCLIReadinessAndCreateFieldConfiguration(t *testing.T) {
	binary := buildTestCLI(t)
	var creates atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/mypermissions"):
			io.WriteString(w, `{"permissions":{"BROWSE_PROJECTS":{"havePermission":true},"CREATE_ISSUES":{"havePermission":true}}}`)
		case strings.HasSuffix(r.URL.Path, "/issuetypes"):
			io.WriteString(w, `{"issueTypes":[{"id":"10001","name":"Bug"}],"total":1}`)
		case strings.HasSuffix(r.URL.Path, "/issuetypes/10001"):
			io.WriteString(w, `{"fields":[{"fieldId":"customfield_10042","required":true}],"total":1}`)
		case strings.HasSuffix(r.URL.Path, "/search/jql"):
			io.WriteString(w, `{"issues":[]}`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/issue"):
			creates.Add(1)
			var body struct {
				Fields map[string]any `json:"fields"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Fields["customfield_10042"] != "configured" {
				t.Error("custom field not sent")
			}
			if _, ok := body.Fields["priority"]; ok {
				t.Error("priority override ignored")
			}
			w.WriteHeader(201)
			io.WriteString(w, `{"key":"SEC-1"}`)
		case strings.Contains(r.URL.Path, "/issue/SEC-1"):
			io.WriteString(w, `{"fields":{"status":{"name":"Open"}}}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	fieldsFile := filepath.Join(dir, "fields.json")
	os.WriteFile(fieldsFile, []byte(`{"customfield_10042":"configured","priority":null}`), 0600)
	env := cleanCLIEnvironment("JIRA_URL="+srv.URL, "JIRA_DEPLOYMENT=cloud", "JIRA_PROJECT=SEC", "JIRA_USER=synthetic@example.invalid", "JIRA_API_TOKEN=synthetic", "JIRA_CREATE_FIELDS_FILE="+fieldsFile)
	cmd := exec.Command(binary, "atlassian", "check", "-remote", "-jira-issue-type=10001")
	cmd.Env = env
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("readiness failed: %s", data)
	}
	var report atlassianCheckOutput
	if json.Unmarshal(data, &report) != nil || report.JiraRemote == nil || !report.JiraRemote.ChecksPassed || report.JiraRemote.CreateVerified || creates.Load() != 0 {
		t.Fatalf("readiness overstated/mutated: %s", data)
	}
	input, run := filepath.Join(dir, "input.json"), filepath.Join(dir, "run.json")
	fixture := policyFixture()
	fixture.Publication = &publication.Result{Stages: []publication.StageResult{{Destination: "old", Stage: "old", Required: true, Status: publication.Failed}}}
	runartifact.Write(input, fixture)
	cmd = exec.Command(binary, "-wizard=false", "-run-in="+input, "-format=entities", "-out="+filepath.Join(dir, "out.json"), "-run-out="+run, "-jira-issue-type=10001", "-include-mitre=false", "-include-cvss=false")
	cmd.Env = env
	data, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("configured create failed: %s", data)
	}
	a, err := runartifact.Read(run)
	if err != nil {
		t.Fatal(err)
	}
	if a.Publication.Err() != nil || stageRecorded(a.Publication, "old", "old") {
		t.Fatal("imported outcomes replayed into new run")
	}
}
