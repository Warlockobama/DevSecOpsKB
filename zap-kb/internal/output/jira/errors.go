package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
)

type apiError struct{ detail publication.Diagnostic }

func (e *apiError) Error() string {
	return fmt.Sprintf("jira: http %d: %s", e.detail.HTTPStatus, e.detail.Message)
}

var customFieldID = regexp.MustCompile(`^customfield_[0-9]{1,12}$`)

func safeFieldID(s string) string {
	switch s {
	case "project", "issuetype", "summary", "description", "priority", "labels", "components", "assignee", "parent", "reporter", "duedate", "fixVersions", "versions", "environment", "security", "timetracking":
		return s
	}
	if customFieldID.MatchString(s) {
		return s
	}
	return "other"
}

// Only known field identifiers and static categories survive. Jira may echo
// arbitrary submitted content or secrets in both errorMessages and errors.
func jiraHTTPErr(resp *http.Response) error {
	d := publication.Diagnostic{HTTPStatus: resp.StatusCode, Category: "http", Message: "Jira rejected the request"}
	switch resp.StatusCode {
	case 400, 422:
		d.Category, d.Message = "rejected", "Check project, issue type, create-screen fields and allowed values"
	case 401:
		d.Category, d.Message = "authentication", "Check the account, token, token scopes and API base URL"
	case 403:
		d.Category, d.Message = "permission", "Check project permissions, issue security and token scopes"
	case 404:
		d.Category, d.Message = "not_found", "Check the API base URL and whether the project or issue is visible to this account"
	case 429:
		d.Category, d.Message, d.Retryable = "rate_limited", "Jira rate limit reached; retry after the server delay", true
	default:
		if resp.StatusCode >= 500 {
			d.Category, d.Message, d.Retryable = "server", "Jira or its gateway is unavailable", true
		}
	}
	var body struct {
		Errors map[string]string `json:"errors"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&body) == nil {
		keys := make([]string, 0, len(body.Errors))
		for k := range body.Errors {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if len(d.Fields) == 16 {
				break
			}
			fd := publication.FieldDiagnostic{Field: safeFieldID(k), Category: "invalid", Message: "Check the field value against project create metadata"}
			v := strings.ToLower(body.Errors[k])
			if strings.Contains(v, "required") {
				fd.Category, fd.Message = "required", "Provide this required create field or configure its project default"
			} else if strings.Contains(v, "cannot be set") || strings.Contains(v, "screen") {
				fd.Category, fd.Message = "not_on_screen", "Make this field available on the create screen or omit it"
			}
			d.Fields = append(d.Fields, fd)
		}
	}
	return &apiError{detail: d}
}

func diagnostic(stage, findingID string, err error) publication.Diagnostic {
	d := publication.Diagnostic{Category: "transport", Retryable: true, Message: "Jira request failed before a usable response; check connectivity"}
	var api *apiError
	var ambiguous *ambiguousCreateError
	switch {
	case errors.As(err, &ambiguous):
		if errors.As(err, &api) {
			d.HTTPStatus = api.detail.HTTPStatus
		}
		d.Category, d.Retryable, d.Message = "ambiguous_create", false, "Create may have succeeded; reconciliation did not establish an issue key. Inspect Jira before retrying publication"
	case errors.As(err, &api):
		d = api.detail
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		d.Category, d.Retryable, d.Message = "canceled", false, "Jira stage was canceled or its deadline expired"
	}
	d.Stage, d.FindingID = stage, findingID
	return d
}
