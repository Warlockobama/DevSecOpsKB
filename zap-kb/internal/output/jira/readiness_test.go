package jira

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadinessCloudMetadataAndRequiredFields(t *testing.T) {
	for _, required := range []bool{false, true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Error("readiness attempted mutation")
			}
			switch r.URL.Path {
			case "/rest/api/3/mypermissions":
				io.WriteString(w, `{"permissions":{"BROWSE_PROJECTS":{"havePermission":true},"CREATE_ISSUES":{"havePermission":true}}}`)
			case "/rest/api/3/issue/createmeta/SEC/issuetypes":
				// Server caps page size at one despite requested maxResults=50.
				if r.URL.Query().Get("startAt") == "0" {
					io.WriteString(w, `{"issueTypes":[{"id":"1","name":"Task"}],"startAt":0,"maxResults":1,"total":2}`)
				} else {
					io.WriteString(w, `{"issueTypes":[{"id":"2","name":"Bug"}],"startAt":1,"maxResults":1,"total":2}`)
				}
			case "/rest/api/3/issue/createmeta/SEC/issuetypes/2":
				json.NewEncoder(w).Encode(map[string]any{"fields": []any{map[string]any{"fieldId": "customfield_10042", "name": "SENSITIVE_NAME", "required": required, "hasDefaultValue": false}}, "total": 1, "startAt": 0, "maxResults": 1})
			default:
				t.Errorf("unexpected diagnostic endpoint: %s", r.URL.Path)
				w.WriteHeader(404)
			}
		}))
		opts := defaultOpts(srv.URL)
		r := CheckReadiness(context.Background(), opts)
		srv.Close()
		if !r.ConfigurationComplete || r.CreateVerified || r.ChecksPassed == required || r.IssueTypeID != "2" {
			t.Fatalf("incorrect readiness: %+v", r)
		}
		data, _ := json.Marshal(r)
		if strings.Contains(string(data), "SENSITIVE") {
			t.Fatal("metadata name leaked")
		}
		if required && (len(r.Diagnostics) != 1 || r.Diagnostics[0].Fields[0].Field != "customfield_10042") {
			t.Fatalf("required field lost: %+v", r)
		}
	}
}

func TestReadinessDoesNotClaimPublishReadyForDeniedOrMalformedMetadata(t *testing.T) {
	for _, body := range []string{`{}`, `{"permissions":{"BROWSE_PROJECTS":{"havePermission":true},"CREATE_ISSUES":{"havePermission":false}}}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		r := CheckReadiness(context.Background(), defaultOpts(srv.URL))
		srv.Close()
		if r.ChecksPassed || len(r.Diagnostics) == 0 {
			t.Fatalf("claimed readiness: %+v", r)
		}
	}
}

func TestCreateFieldCustomizationPreservesIdentityAndWorkflow(t *testing.T) {
	for _, field := range []string{"labels", "project", "summary", "description", "issuetype", "status", "transitions", "SENSITIVE_FIELD"} {
		if ValidateCreateFields(map[string]any{field: "x"}) == nil {
			t.Errorf("accepted reserved field %s", field)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/search/jql") {
			json.NewEncoder(w).Encode(searchResponse(""))
			return
		}
		var body struct {
			Fields map[string]any `json:"fields"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body.Fields["priority"]; ok {
			t.Error("null override did not omit priority")
		}
		if body.Fields["issuetype"].(map[string]any)["id"] != "10001" || body.Fields["customfield_10042"] != "configured" {
			t.Errorf("customization missing: %+v", body.Fields)
		}
		if body.Fields["labels"].([]any)[0] != "zap-finding-fin" {
			t.Error("dedup identity changed")
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"key":"SEC-1"}`)
	}))
	defer srv.Close()
	opts := defaultOpts(srv.URL)
	opts.IssueType = "10001"
	opts.RequestDelay = -1
	opts.CreateFields = map[string]any{"priority": nil, "customfield_10042": "configured"}
	sum, err := Export(context.Background(), makeEntities(makeFinding("fin", "high", "https://example.test")), opts)
	if err != nil || sum.Created != 1 {
		t.Fatalf("customization failed: %+v %v", sum, err)
	}
}
