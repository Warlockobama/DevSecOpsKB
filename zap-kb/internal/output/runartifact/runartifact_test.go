package runartifact

import (
	"os"
	"path/filepath"
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
