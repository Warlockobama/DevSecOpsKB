package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/synccore"
)

// ReadinessReport distinguishes read-only evidence from actual create/readback
// acceptance. Passing checks cannot prove a future issue will be accepted.
type ReadinessReport struct {
	ConfigurationComplete bool                     `json:"configurationComplete"`
	ChecksPassed          bool                     `json:"checksPassed"`
	CreateVerified        bool                     `json:"createVerified"`
	Checked               []string                 `json:"checked"`
	IssueTypeID           string                   `json:"issueTypeId,omitempty"`
	RequiredFields        []string                 `json:"requiredFields,omitempty"`
	Diagnostics           []publication.Diagnostic `json:"diagnostics,omitempty"`
}

// CheckReadiness performs bounded, read-only checks of project permissions and
// paginated create metadata. It does not require the optional /myself endpoint
// (which has its own user-read scope) and never writes a diagnostic issue.
func CheckReadiness(ctx context.Context, opts Options) ReadinessReport {
	r := ReadinessReport{Checked: []string{"configuration"}}
	if strings.TrimSpace(opts.BaseURL) == "" || strings.TrimSpace(opts.ProjectKey) == "" || strings.TrimSpace(opts.APIToken) == "" {
		r.Diagnostics = append(r.Diagnostics, publication.Diagnostic{Stage: "readiness", Category: "configuration", Message: "Base URL, project key and API credential are required"})
		return r
	}
	if err := ValidateCreateFields(opts.CreateFields); err != nil {
		r.Diagnostics = append(r.Diagnostics, publication.Diagnostic{Stage: "configuration", Category: "configuration", Message: "Create-fields contains a reserved or unsupported field"})
		return r
	}
	r.ConfigurationComplete = true
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 5 * time.Second}
	base := issueAPI(strings.TrimRight(opts.BaseURL, "/"), isDataCenter(opts.Deployment))
	auth := synccore.AuthHeader(opts.Username, opts.APIToken)
	get := func(path string, out any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", auth)
		req.Header.Set("Accept", "application/json")
		resp, err := doRequest(client, req, 1)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(out)
	}
	fail := func(stage string, err error) ReadinessReport {
		r.Diagnostics = append(r.Diagnostics, diagnostic(stage, "", err))
		return r
	}
	var perms struct {
		Permissions map[string]struct {
			HavePermission bool `json:"havePermission"`
		} `json:"permissions"`
	}
	r.Checked = append(r.Checked, "project Browse Projects and Create Issues permissions")
	if err := get("/mypermissions?projectKey="+url.QueryEscape(opts.ProjectKey)+"&permissions=BROWSE_PROJECTS,CREATE_ISSUES", &perms); err != nil {
		return fail("permissions", err)
	}
	for _, key := range []string{"BROWSE_PROJECTS", "CREATE_ISSUES"} {
		if !perms.Permissions[key].HavePermission {
			r.Diagnostics = append(r.Diagnostics, publication.Diagnostic{Stage: "permissions", Category: "permission", Message: "Project requires both Browse Projects and Create Issues permissions"})
			return r
		}
	}
	issueType := strings.TrimSpace(opts.IssueType)
	if issueType == "" {
		issueType = "Bug"
	}
	metaPath := "/issue/createmeta/" + url.PathEscape(opts.ProjectKey) + "/issuetypes"
	r.Checked = append(r.Checked, "project issue type create metadata")
	for page, start := 0, 0; page < 10; page++ {
		var types struct {
			IssueTypes []metaIssueType `json:"issueTypes"`
			Values     []metaIssueType `json:"values"`
			IsLast     bool            `json:"isLast"`
			Total      *int            `json:"total"`
		}
		if err := get(metaPath+"?startAt="+strconv.Itoa(start)+"&maxResults=50", &types); err != nil {
			return fail("issue_type_metadata", err)
		}
		items := types.IssueTypes
		if items == nil {
			items = types.Values
		}
		if items == nil {
			return fail("issue_type_metadata", fmt.Errorf("missing issue types in metadata"))
		}
		for _, typ := range items {
			if typ.ID == issueType || strings.EqualFold(typ.Name, issueType) {
				if !issueTypeID.MatchString(typ.ID) {
					return fail("issue_type_metadata", fmt.Errorf("invalid issue type ID in metadata"))
				}
				r.IssueTypeID = typ.ID
				break
			}
		}
		start += len(items)
		if r.IssueTypeID != "" || types.IsLast || (types.Total != nil && start >= *types.Total) || len(items) == 0 {
			break
		}
	}
	if r.IssueTypeID == "" {
		r.Diagnostics = append(r.Diagnostics, publication.Diagnostic{Stage: "issue_type_metadata", Category: "configuration", Message: "Configured issue type was not found in bounded project create metadata"})
		return r
	}
	r.Checked = append(r.Checked, "required create fields (values and create not verified)")
	for page, start := 0, 0; page < 10; page++ {
		var fields struct {
			Fields []metaField `json:"fields"`
			Values []metaField `json:"values"`
			IsLast bool        `json:"isLast"`
			Total  *int        `json:"total"`
		}
		if err := get(metaPath+"/"+url.PathEscape(r.IssueTypeID)+"?startAt="+strconv.Itoa(start)+"&maxResults=50", &fields); err != nil {
			return fail("field_metadata", err)
		}
		items := fields.Fields
		if items == nil {
			items = fields.Values
		}
		if items == nil {
			return fail("field_metadata", fmt.Errorf("missing fields in metadata"))
		}
		for _, field := range items {
			if !field.Required {
				continue
			}
			id := field.FieldID
			if id == "" {
				id = field.Key
			}
			id = safeFieldID(id)
			r.RequiredFields = append(r.RequiredFields, id)
			if field.HasDefaultValue {
				continue
			}
			supplied := false
			switch id {
			case "project", "issuetype", "summary", "description", "priority", "labels":
				supplied = true
			case "components":
				supplied = strings.TrimSpace(opts.Component) != ""
			case "parent":
				supplied = opts.DetectionEpic
			}
			if value, configured := opts.CreateFields[id]; configured {
				supplied = value != nil
			}
			if !supplied {
				r.Diagnostics = append(r.Diagnostics, publication.Diagnostic{Stage: "field_metadata", Category: "required_field", Message: "A required field needs a configured value or project default", Fields: []publication.FieldDiagnostic{{Field: id, Category: "required", Message: "Provide this field using Jira create-fields configuration or set a project default"}}})
			}
		}
		start += len(items)
		if len(items) == 0 && !fields.IsLast && (fields.Total == nil || start < *fields.Total) {
			return fail("field_metadata", fmt.Errorf("incomplete metadata pagination"))
		}
		if fields.IsLast || (fields.Total != nil && start >= *fields.Total) {
			r.ChecksPassed = len(r.Diagnostics) == 0
			return r
		}
	}
	return fail("field_metadata", fmt.Errorf("metadata pagination exceeded bounded page limit"))
}

type metaIssueType struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type metaField struct {
	FieldID         string `json:"fieldId"`
	Key             string `json:"key"`
	Required        bool   `json:"required"`
	HasDefaultValue bool   `json:"hasDefaultValue"`
}
