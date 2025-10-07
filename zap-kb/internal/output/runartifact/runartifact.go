package runartifact

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jsondump"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
)

// Meta captures pipeline/run context so KB pages can reflect state across runs.
type Meta struct {
	SourceTool       string `json:"sourceTool,omitempty"`
	GeneratedAt      string `json:"generatedAt,omitempty"`
	ScanLabel        string `json:"scanLabel,omitempty"`
	SiteLabel        string `json:"siteLabel,omitempty"`
	ZapBaseURL       string `json:"zapBaseUrl,omitempty"`
	BaseURL          string `json:"baseUrl,omitempty"`
	Commit           string `json:"commit,omitempty"`
	Branch           string `json:"branch,omitempty"`
	PipelineRun      string `json:"pipelineRun,omitempty"`
	DetectionDetails string `json:"detectionDetails,omitempty"`
	IncludeTraffic   bool   `json:"includeTraffic,omitempty"`
}

// Artifact is a pipeline-friendly wrapper that includes normalized entities and
// optionally the raw alerts. Meant to be uploaded as a build artifact and later
// re-imported to (re)publish the KB.
type Artifact struct {
	Schema   string                `json:"schema"` // e.g., "zap-kb/run/v1"
	Meta     Meta                  `json:"meta"`
	Entities entities.EntitiesFile `json:"entities"`
	Alerts   []zapclient.Alert     `json:"alerts,omitempty"`
}

func Write(path string, a Artifact) error {
	if a.Schema == "" {
		a.Schema = "zap-kb/run/v1"
	}
	return jsondump.WritePretty(path, a)
}

// Read reads a run artifact strictly.
func Read(path string) (Artifact, error) {
	var a Artifact
	f, err := os.Open(path)
	if err != nil {
		return a, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	err = dec.Decode(&a)
	return a, err
}

// ReadFlexible accepts either a full run artifact or a bare Entities JSON.
// In the latter case, Meta remains empty and Alerts nil.
func ReadFlexible(path string) (Artifact, error) {
	a, err := Read(path)
	if err == nil && a.Entities.SchemaVersion != "" {
		return a, nil
	}
	// Try as bare entities JSON
	var ent entities.EntitiesFile
	f, err2 := os.Open(path)
	if err2 != nil {
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{}, fmt.Errorf("open entities JSON %q: %w", path, err2)
	}
	defer f.Close()
	if err3 := json.NewDecoder(f).Decode(&ent); err3 != nil {
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{}, fmt.Errorf("decode entities JSON %q: %w", path, err3)
	}
	if strings.TrimSpace(ent.SchemaVersion) == "" && len(ent.Definitions) == 0 && len(ent.Occurrences) == 0 {
		if err != nil {
			return Artifact{}, err
		}
		return Artifact{}, fmt.Errorf("%s does not look like a zap-kb entities file", path)
	}
	return Artifact{Schema: "zap-kb/run/v1", Entities: ent}, nil
}
