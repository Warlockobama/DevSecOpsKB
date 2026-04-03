package entities

import (
	"encoding/json"
	"testing"
)

func TestNormalizeImportJSON_WASCIDStringToInt(t *testing.T) {
	input := `{"definitions":[{"definitionId":"def-x","pluginId":"x","wascid":"2"}],"findings":[],"occurrences":[]}`
	out, err := NormalizeImportJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var ef EntitiesFile
	if err := json.Unmarshal(out, &ef); err != nil {
		t.Fatalf("unmarshal after normalize: %v", err)
	}
	if ef.Definitions[0].WASCID != 2 {
		t.Errorf("expected wascid=2, got %d", ef.Definitions[0].WASCID)
	}
}

func TestNormalizeImportJSON_RiskCodeIntToString(t *testing.T) {
	input := `{"definitions":[],"findings":[{"findingId":"fin-x","definitionId":"def-x","pluginId":"x","url":"/","method":"GET","riskcode":4,"occurrenceCount":1}],"occurrences":[{"occurrenceId":"occ-x","definitionId":"def-x","findingId":"fin-x","url":"/","riskcode":3}]}`
	out, err := NormalizeImportJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var ef EntitiesFile
	if err := json.Unmarshal(out, &ef); err != nil {
		t.Fatalf("unmarshal after normalize: %v", err)
	}
	if ef.Findings[0].RiskCode != "4" {
		t.Errorf("expected finding riskcode='4', got %q", ef.Findings[0].RiskCode)
	}
	if ef.Occurrences[0].RiskCode != "3" {
		t.Errorf("expected occurrence riskcode='3', got %q", ef.Occurrences[0].RiskCode)
	}
}

func TestNormalizeImportJSON_HeadersStringToStruct(t *testing.T) {
	input := `{"definitions":[],"findings":[],"occurrences":[{"occurrenceId":"occ-x","definitionId":"def-x","findingId":"fin-x","url":"/","request":{"headers":["Authorization: Bearer tok","Content-Type: application/json"]},"response":{"headers":["Content-Type: text/html"],"statusCode":200}}]}`
	out, err := NormalizeImportJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var ef EntitiesFile
	if err := json.Unmarshal(out, &ef); err != nil {
		t.Fatalf("unmarshal after normalize: %v", err)
	}
	occ := ef.Occurrences[0]
	if occ.Request == nil || len(occ.Request.Headers) != 2 {
		t.Fatalf("expected 2 request headers, got %v", occ.Request)
	}
	if occ.Request.Headers[0].Name != "Authorization" {
		t.Errorf("expected Authorization header, got %q", occ.Request.Headers[0].Name)
	}
	if occ.Request.Headers[0].Value != "Bearer tok" {
		t.Errorf("expected 'Bearer tok', got %q", occ.Request.Headers[0].Value)
	}
	if occ.Response == nil || len(occ.Response.Headers) != 1 {
		t.Fatalf("expected 1 response header, got %v", occ.Response)
	}
}

func TestNormalizeImportJSON_AlreadyCorrectTypes(t *testing.T) {
	input := `{"definitions":[{"definitionId":"def-x","pluginId":"x","wascid":2}],"findings":[{"findingId":"fin-x","definitionId":"def-x","pluginId":"x","url":"/","method":"GET","riskcode":"4","occurrenceCount":1}],"occurrences":[]}`
	out, err := NormalizeImportJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var ef EntitiesFile
	if err := json.Unmarshal(out, &ef); err != nil {
		t.Fatalf("unmarshal after normalize: %v", err)
	}
	if ef.Definitions[0].WASCID != 2 {
		t.Errorf("expected wascid=2, got %d", ef.Definitions[0].WASCID)
	}
	if ef.Findings[0].RiskCode != "4" {
		t.Errorf("expected riskcode='4', got %q", ef.Findings[0].RiskCode)
	}
}

func TestNormalizeImportJSON_ReproduceFieldRoundTrips(t *testing.T) {
	input := `{"definitions":[],"findings":[],"occurrences":[{"occurrenceId":"occ-x","definitionId":"def-x","findingId":"fin-x","url":"/","reproduce":{"curl":"curl -i http://example.com","steps":["step one","step two"]}}]}`
	out, err := NormalizeImportJSON([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var ef EntitiesFile
	if err := json.Unmarshal(out, &ef); err != nil {
		t.Fatalf("unmarshal after normalize: %v", err)
	}
	occ := ef.Occurrences[0]
	if occ.Reproduce == nil {
		t.Fatal("Reproduce should not be nil")
	}
	if occ.Reproduce.Curl != "curl -i http://example.com" {
		t.Errorf("unexpected curl: %q", occ.Reproduce.Curl)
	}
	if len(occ.Reproduce.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(occ.Reproduce.Steps))
	}
}
