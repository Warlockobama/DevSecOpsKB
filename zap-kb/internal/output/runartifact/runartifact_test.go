package runartifact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
)

func TestReadFlexibleDerivesRequestForStrictArtifactResponseOnlyOccurrence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.json")
	input := `{
  "schema": "zap-kb/run/v1",
  "meta": {"sourceTool": "multi"},
  "entities": {
    "schemaVersion": "v1",
    "sourceTool": "multi",
    "definitions": [{"definitionId":"def-zap-legacy-ftp-surface","pluginId":"zap-legacy-ftp-surface"}],
    "findings": [{"findingId":"fin-3168b4d6","definitionId":"def-zap-legacy-ftp-surface","pluginId":"zap-legacy-ftp-surface","url":"http://juice-shop.range.svc.cluster.local:3000/ftp","method":"GET","occurrenceCount":1}],
    "occurrences": [{
      "occurrenceId": "occ-5a69bfa6",
      "definitionId": "def-zap-legacy-ftp-surface",
      "findingId": "fin-3168b4d6",
      "url": "http://juice-shop.range.svc.cluster.local:3000/ftp",
      "method": "GET",
      "response": {
        "statusCode": 200,
        "headers": [{"name": "Content-Type", "value": "text/html"}],
        "bodyBytes": 11306
      }
    }]
  }
}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	artifact, err := ReadFlexible(path)
	if err != nil {
		t.Fatalf("ReadFlexible: %v", err)
	}
	req := artifact.Entities.Occurrences[0].Request
	if req == nil {
		t.Fatal("expected derived request")
	}
	if req.DerivedFrom != entities.RequestDerivedFromOccurrence {
		t.Fatalf("DerivedFrom = %q, want %q", req.DerivedFrom, entities.RequestDerivedFromOccurrence)
	}
	if req.BodyBytes != 0 || req.BodySnippet != "" {
		t.Fatalf("derived request should not invent a body: bytes=%d snippet=%q", req.BodyBytes, req.BodySnippet)
	}
}

func TestReadValidatedCompatibilityFixtures(t *testing.T) {
	tests := []struct {
		name           string
		fixture        string
		format         InputFormat
		normalizations int
	}{
		{name: "declared empty entities", fixture: "valid-empty-entities.json", format: FormatEntities},
		{name: "Forgejo publisher fixture", fixture: "valid-forgejo-publisher-e2e.json", format: FormatEntities},
		{name: "definitions only legacy scalar", fixture: "valid-definitions-only-legacy.json", format: FormatEntities, normalizations: 1},
		{name: "Cactus wrapper", fixture: "valid-cactus-run.json", format: FormatRunWrapper},
		{name: "firing range wrapper", fixture: "valid-firing-range-run.json", format: FormatRunWrapper, normalizations: 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifact, result, err := ReadValidated(validationFixture(tc.fixture))
			if err != nil {
				t.Fatalf("ReadValidated: %v", err)
			}
			if result.Format != tc.format || result.EntitiesSchema != entities.SupportedSchemaVersion {
				t.Fatalf("unexpected validation result: %+v", result)
			}
			if len(result.Normalizations) != tc.normalizations {
				t.Fatalf("normalizations = %+v, want %d", result.Normalizations, tc.normalizations)
			}
			if artifact.Entities.Definitions == nil || artifact.Entities.Findings == nil || artifact.Entities.Occurrences == nil {
				t.Fatal("validated collections must be declared, non-nil slices")
			}
		})
	}
}

func TestForgejoPublisherFixtureContainsEligibleFinding(t *testing.T) {
	ent, _, err := ReadEntities(validationFixture("valid-forgejo-publisher-e2e.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ent.Findings) != 1 || ent.Findings[0].Risk != "High" || len(ent.Occurrences) != 1 {
		t.Fatalf("fixture must exercise one high-risk finding and occurrence: %+v", ent)
	}
}

func TestReadValidatedPreservesCactusDetectionTrace(t *testing.T) {
	artifact, _, err := ReadValidated(validationFixture("valid-cactus-run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Entities.Occurrences) != 1 {
		t.Fatalf("occurrences = %d, want 1", len(artifact.Entities.Occurrences))
	}
	other := artifact.Entities.Occurrences[0].Other
	var provenance map[string]interface{}
	if err := json.Unmarshal([]byte(other), &provenance); err != nil {
		t.Fatalf("Cactus occurrence provenance: %v", err)
	}
	trace, ok := provenance["detectionTrace"].(map[string]interface{})
	if !ok || trace["schemaVersion"] != "detection-trace.v1" {
		t.Fatalf("detection trace not preserved: %s", other)
	}
}

func TestReadValidatedNormalizesHistoricalNullCollections(t *testing.T) {
	path := writeInput(t, `{"schemaVersion":"v1","generatedAt":"2026-09-12T12:00:00Z","sourceTool":"zap","definitions":null,"findings":null,"occurrences":null}`)
	artifact, result, err := ReadValidated(path)
	if err != nil {
		t.Fatalf("ReadValidated: %v", err)
	}
	if len(result.Normalizations) != 3 {
		t.Fatalf("normalizations = %+v, want three null conversions", result.Normalizations)
	}
	if artifact.Entities.Definitions == nil || artifact.Entities.Findings == nil || artifact.Entities.Occurrences == nil {
		t.Fatal("null collections were not normalized to empty arrays")
	}
}

func TestWriteReadEmptyArtifactRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.json")
	original := Artifact{
		Schema:   SchemaV1,
		Meta:     Meta{SourceTool: "zap", GeneratedAt: "2026-09-12T12:00:00Z", ScanLabel: "empty-scan"},
		Entities: entities.EntitiesFile{SchemaVersion: "v1", SourceTool: "zap", GeneratedAt: "2026-09-12T12:00:00Z"},
	}
	if err := Write(path, original); err != nil {
		t.Fatalf("Write: %v", err)
	}
	readBack, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if readBack.Entities.GeneratedAt != original.Entities.GeneratedAt || readBack.Meta.ScanLabel != original.Meta.ScanLabel {
		t.Fatalf("empty metadata changed: %+v", readBack)
	}
}

func TestReadValidatedRejectsMalformedAndIncompatibleDocuments(t *testing.T) {
	validCollections := `"definitions":[],"findings":[],"occurrences":[]`
	tests := []struct {
		name string
		json string
		want string
	}{
		{name: "empty object", json: `{}`, want: "definitions: missing required collection"},
		{name: "unsupported entities version", json: `{"schemaVersion":"v999",` + validCollections + `}`, want: "schemaVersion: unsupported version"},
		{name: "truncated", json: `{"schemaVersion":"v1",`, want: "document: invalid JSON object"},
		{name: "trailing document", json: `{"schemaVersion":"v1",` + validCollections + `}{}`, want: "document: trailing JSON value"},
		{name: "wrong collection", json: `{"schemaVersion":"v1","definitions":{},"findings":[],"occurrences":[]}`, want: "definitions: wrong collection type"},
		{name: "duplicate definition ID", json: `{"schemaVersion":"v1","definitions":[{"definitionId":"def-1","pluginId":"1"},{"definitionId":"def-1","pluginId":"1"}],"findings":[],"occurrences":[]}`, want: "definitions[1].definitionId: duplicate ID"},
		{name: "dangling finding reference", json: `{"schemaVersion":"v1","definitions":[],"findings":[{"findingId":"fin-1","definitionId":"def-1","pluginId":"1"}],"occurrences":[]}`, want: "findings[0].definitionId: dangling reference"},
		{name: "duplicate finding ID", json: `{"schemaVersion":"v1","definitions":[{"definitionId":"def-1","pluginId":"1"}],"findings":[{"findingId":"fin-1","definitionId":"def-1","pluginId":"1"},{"findingId":"fin-1","definitionId":"def-1","pluginId":"1"}],"occurrences":[]}`, want: "findings[1].findingId: duplicate ID"},
		{name: "duplicate occurrence ID", json: `{"schemaVersion":"v1","definitions":[{"definitionId":"def-1","pluginId":"1"}],"findings":[{"findingId":"fin-1","definitionId":"def-1","pluginId":"1"}],"occurrences":[{"occurrenceId":"occ-1","definitionId":"def-1","findingId":"fin-1"},{"occurrenceId":"occ-1","definitionId":"def-1","findingId":"fin-1"}]}`, want: "occurrences[1].occurrenceId: duplicate ID"},
		{name: "invalid timestamp", json: `{"schemaVersion":"v1","generatedAt":"SYNTHETIC_SENSITIVE_MARKER",` + validCollections + `}`, want: "generatedAt: invalid RFC3339 timestamp"},
		{name: "whitespace ID", json: `{"schemaVersion":"v1","definitions":[{"definitionId":" def-1","pluginId":"1"}],"findings":[],"occurrences":[]}`, want: "definitions[0].definitionId: surrounding whitespace"},
		{name: "plugin mismatch", json: `{"schemaVersion":"v1","definitions":[{"definitionId":"def-1","pluginId":"1"}],"findings":[{"findingId":"fin-1","definitionId":"def-1","pluginId":"2"}],"occurrences":[]}`, want: "findings[0].pluginId: inconsistent with definition reference"},
		{name: "wrapper version", json: `{"schema":"zap-kb/run/v999","meta":{},"entities":{"schemaVersion":"v1",` + validCollections + `}}`, want: "schema: unsupported version"},
		{name: "wrapper entity version", json: `{"schema":"zap-kb/run/v1","meta":{},"entities":{"schemaVersion":"v999",` + validCollections + `}}`, want: "entities.schemaVersion: unsupported version"},
		{name: "wrapper source mismatch", json: `{"schema":"zap-kb/run/v1","meta":{"sourceTool":"zap"},"entities":{"schemaVersion":"v1","sourceTool":"other",` + validCollections + `}}`, want: "meta.sourceTool/entities.sourceTool: inconsistent wrapper metadata"},
		{name: "wrapper timestamp mismatch", json: `{"schema":"zap-kb/run/v1","meta":{"generatedAt":"2026-09-12T12:00:00Z"},"entities":{"schemaVersion":"v1","generatedAt":"2026-09-12T12:01:00Z",` + validCollections + `}}`, want: "meta.generatedAt/entities.generatedAt: inconsistent wrapper metadata"},
		{name: "wrapper cannot fall back", json: `{"schema":"zap-kb/run/v999","meta":{},"entities":{},"schemaVersion":"v1",` + validCollections + `}`, want: "schema: unsupported version"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ReadValidated(writeInput(t, tc.json))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "SYNTHETIC_SENSITIVE_MARKER") {
				t.Fatalf("diagnostic leaked rejected value: %v", err)
			}
		})
	}
}

func TestStrictReadersKeepFormatBoundary(t *testing.T) {
	if _, err := Read(validationFixture("valid-empty-entities.json")); err == nil || err.Error() != "document: expected run wrapper" {
		t.Fatalf("Read bare entities error = %v", err)
	}
	if _, _, err := ReadEntities(validationFixture("valid-cactus-run.json")); err == nil || err.Error() != "document: expected bare entities" {
		t.Fatalf("ReadEntities wrapper error = %v", err)
	}
}

func validationFixture(name string) string {
	return filepath.Join("..", "..", "..", "testdata", "validation", name)
}

func writeInput(t *testing.T, input string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
