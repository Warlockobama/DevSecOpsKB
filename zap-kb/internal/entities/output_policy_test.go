package entities

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOutputPolicyMetadataAndEvidenceInventory(t *testing.T) {
	const graphID = "0123456789abcdef0123456789abcdef01234567"
	const raw = `{"schema":"detection-trace.v1","score":9007199254740993,"signals":[{"rule":"safe-rule","weight":4,"url":"https://private.invalid/a?q=QUERY_MARKER","Cookie":"COOKIE_MARKER","Authorization":"AUTH_MARKER","X-Api-Key":"HEADER_MARKER","body":"BODY_MARKER","notes":"NOTE_MARKER","email":"SECRET_MARKER@example.invalid"}],"query":{"page":"QUERY_MARKER"},"host":"private.invalid"}`
	all := ParseRedactOptionList("domain,query,cookies,auth,headers,body,notes,secrets")
	e := EntitiesFile{SchemaVersion: "v1", SourceTool: "cactus-sheriff", Definitions: []Definition{{DefinitionID: graphID, PluginID: "rule", Description: "Useful context; contact SECRET_MARKER@example.invalid", Taxonomy: &Taxonomy{ATTACK: []string{"T1190"}}}}, Findings: []Finding{{FindingID: graphID, DefinitionID: graphID, PluginID: "rule", URL: "https://private.invalid/a?q=QUERY_MARKER", Analyst: &Analyst{Status: "triaged", History: []AnalystHistoryEntry{{EntryID: graphID, ScanLabel: "scan-1", Status: "open", Notes: "NOTE_MARKER"}}}}}, Occurrences: []Occurrence{{OccurrenceID: graphID, DefinitionID: graphID, FindingID: graphID, ScanLabel: "scan-1", Other: raw, Request: &HTTPRequest{BodySnippet: "BODY_MARKER", BodyBytes: 100, BodyHash: graphID}, Reproduce: &Reproduce{Curl: `curl -b 'COOKIE_MARKER' --user 'AUTH_MARKER' https://private.invalid/a?q=QUERY_MARKER`}}}}
	RedactEntities(&e, all)
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"QUERY_MARKER", "COOKIE_MARKER", "AUTH_MARKER", "HEADER_MARKER", "BODY_MARKER", "NOTE_MARKER", "SECRET_MARKER", "private.invalid"} {
		if strings.Contains(string(b), marker) {
			t.Errorf("output leaked %s", marker)
		}
	}
	if e.Findings[0].FindingID != graphID || e.Occurrences[0].OccurrenceID != graphID || e.Definitions[0].DefinitionID != graphID || e.Findings[0].Analyst.History[0].EntryID != graphID {
		t.Fatal("identity changed")
	}
	if e.SourceTool != "cactus-sheriff" || e.Occurrences[0].ScanLabel != "scan-1" || e.Findings[0].Analyst.Status != "triaged" {
		t.Fatal("source or analyst state changed")
	}
	if !strings.Contains(e.Occurrences[0].Other, `9007199254740993`) || !strings.Contains(e.Occurrences[0].Other, `detection-trace.v1`) || !strings.Contains(e.Occurrences[0].Other, `safe-rule`) {
		t.Fatal("trace structure or exact number lost")
	}
	if e.Definitions[0].Taxonomy.ATTACK[0] != "T1190" || e.Occurrences[0].Request.BodyBytes != 100 || e.Occurrences[0].Request.BodyHash != graphID {
		t.Fatal("nonsensitive evidence lost")
	}
	RedactEntities(&e, all)
	twice, _ := json.Marshal(e)
	if string(twice) != string(b) {
		t.Fatalf("redaction is not idempotent: first=%s second=%s", b, twice)
	}

}

func TestOutputPolicyModeIsolation(t *testing.T) {
	cases := []struct{ mode, input string }{
		{"query", `curl 'https://example.invalid/a?q=PRIVATE_MARKER' /a?q=PRIVATE_MARKER`},
		{"cookies", `curl -b 'PRIVATE_MARKER' -H 'Cookie: PRIVATE_MARKER'`},
		{"auth", `curl --user 'PRIVATE_MARKER' -H 'Authorization: PRIVATE_MARKER' https://user:PRIVATE_MARKER@example.invalid/a`},
		{"headers", `X-Api-Key: PRIVATE_MARKER`},
		{"secrets", `password=PRIVATE_MARKER PRIVATE_MARKER@example.invalid`},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			ro, err := ParseRedactOptions(tc.mode)
			if err != nil {
				t.Fatal(err)
			}
			if got := RedactText(tc.input, ro); strings.Contains(got, "PRIVATE_MARKER") {
				t.Fatalf("mode leak: %s", got)
			}
		})
	}
	if got := RedactText("SQLITE_ERROR useful context", ParseRedactOptionList("secrets")); got != "SQLITE_ERROR useful context" {
		t.Fatal("safe context lost")
	}
	if _, err := ParseRedactOptions("query,PRIVATE_MARKER"); err == nil || strings.Contains(err.Error(), "PRIVATE_MARKER") {
		t.Fatal("invalid mode must fail safely")
	}
}

func TestOutputPolicyNestedMetadataAndTrailingText(t *testing.T) {
	var e struct {
		Other string `json:"other"`
	}
	e.Other = `{"schema":"detection-trace.v1","weight":4,"requestBody":{"nested":"BODY_MARKER"},"notes":{"comment":"NOTE_MARKER"},"token":123456,"Authorization":["AUTH_MARKER"]}`
	RedactOutput(&e, ParseRedactOptionList("body,notes,secrets,auth"))
	for _, v := range []string{"BODY_MARKER", "NOTE_MARKER", "123456", "AUTH_MARKER"} {
		if strings.Contains(e.Other, v) {
			t.Errorf("nested leak: %s", v)
		}
	}
	if !strings.Contains(e.Other, `"weight":4`) || !strings.Contains(e.Other, "detection-trace.v1") {
		t.Fatal("trace metadata lost")
	}
	e.Other = `{"safe":true} useful trailing context Cookie: COOKIE_MARKER`
	RedactOutput(&e, ParseRedactOptionList("cookies"))
	if !strings.Contains(e.Other, "useful trailing context") || strings.Contains(e.Other, "COOKIE_MARKER") {
		t.Fatal("trailing text lost or leaked")
	}
}
