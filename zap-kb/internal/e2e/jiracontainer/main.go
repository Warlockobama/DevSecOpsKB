// jira-stub is a deliberately small, private-network fixture for the
// container contract test. It implements only the Jira routes that the test
// asserts and never records request bodies or authorization headers.
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

func main() {
	mode := os.Getenv("JIRA_STUB_MODE")
	if mode == "" {
		mode = "accept"
	}
	created := false
	logRequest := func(r *http.Request) {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
			"method": r.Method,
			"path":   r.URL.Path,
		})
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logRequest(r)
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		if strings.HasPrefix(path, "/ex/jira/mock-cloud/") {
			path = strings.TrimPrefix(path, "/ex/jira/mock-cloud")
		}

		switch {
		case path == "/ready":
			_, _ = w.Write([]byte(`{"ready":true}`))
		case path == "/rest/api/3/search/jql":
			if created {
				_, _ = w.Write([]byte(`{"issues":[{"key":"TEST-1"}],"isLast":true}`))
				return
			}
			_, _ = w.Write([]byte(`{"issues":[],"isLast":true}`))
		case path == "/rest/api/3/search":
			w.WriteHeader(http.StatusGone)
			_, _ = w.Write([]byte(`{"errorMessages":["use enhanced search/jql"]}`))
		case path == "/rest/api/3/issue" && r.Method == http.MethodPost:
			if mode == "reject" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":{"issuetype":"synthetic unsupported issue type"}}`))
				return
			}
			created = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"10001","key":"TEST-1","self":"http://jira.atlassian.net:8080/rest/api/3/issue/10001"}`))
		case path == "/rest/api/3/issue/TEST-1" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"key":"TEST-1","fields":{"status":{"name":"Open"},"assignee":null}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorMessages":["synthetic unsupported API path"]}`))
		}
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
