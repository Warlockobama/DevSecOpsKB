package runartifact

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/jsondump"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/zapclient"
)

const SchemaV1 = "zap-kb/run/v1"

type InputFormat string

const (
	FormatEntities   InputFormat = "entities-v1"
	FormatRunWrapper InputFormat = "run-v1"
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
	Publication *publication.Result   `json:"publication,omitempty"`
	Schema      string                `json:"schema"`
	Meta        Meta                  `json:"meta"`
	Entities    entities.EntitiesFile `json:"entities"`
	Alerts      []zapclient.Alert     `json:"alerts,omitempty"`
}

// ValidationResult describes the accepted document format and any documented
// producer normalizations applied before typed decoding. It is returned for
// both bare entities and wrappers so downstream boundaries use one contract.
type ValidationResult struct {
	Format         InputFormat
	Schema         string
	EntitiesSchema string
	Normalizations []entities.ImportNormalization
	Issues         []entities.ValidationIssue
}

func (r ValidationResult) OK() bool { return len(r.Issues) == 0 }

func (r ValidationResult) Err() error {
	if r.OK() {
		return nil
	}
	return r.Issues[0]
}

func Write(path string, a Artifact) error {
	if a.Schema == "" {
		a.Schema = SchemaV1
	}
	entities.EnsureCollections(&a.Entities)
	if result := ValidateArtifact(a); !result.OK() {
		return result.Err()
	}
	return jsondump.WritePretty(path, a)
}

// ValidateArtifact validates an in-memory wrapper before serialization. Empty
// nil slices are allowed here because Write canonicalizes them to arrays.
func ValidateArtifact(a Artifact) ValidationResult {
	result := ValidationResult{
		Format:         FormatRunWrapper,
		Schema:         strings.TrimSpace(a.Schema),
		EntitiesSchema: strings.TrimSpace(a.Entities.SchemaVersion),
	}
	if strings.TrimSpace(a.Schema) != SchemaV1 {
		result.Issues = append(result.Issues, fieldError("schema", "unsupported version"))
		return result
	}
	entityResult := entities.Validate(a.Entities)
	for _, issue := range entityResult.Issues {
		issue.Path = joinPath("entities", issue.Path)
		result.Issues = append(result.Issues, issue)
	}
	if err := validateMetaConsistency(a.Meta, a.Entities); err != nil {
		if issue, ok := err.(entities.ValidationIssue); ok {
			result.Issues = append(result.Issues, issue)
		}
	}
	return result
}

// Read reads and validates a run wrapper. Wrapper-shaped malformed input is
// never retried as bare entities.
func Read(path string) (Artifact, error) {
	a, _, err := readValidated(path, FormatRunWrapper)
	return a, err
}

// ReadEntities reads and validates only a bare entities document.
func ReadEntities(path string) (entities.EntitiesFile, ValidationResult, error) {
	a, result, err := readValidated(path, FormatEntities)
	return a.Entities, result, err
}

// ReadFlexible accepts and validates either a full run artifact or a bare
// entities document. In the latter case, Meta remains empty and Alerts nil.
func ReadFlexible(path string) (Artifact, error) {
	a, _, err := ReadValidated(path)
	return a, err
}

// ReadValidated accepts both supported formats and returns the shared
// compatibility result. ReadFlexible retains its historical signature.
func ReadValidated(path string) (Artifact, ValidationResult, error) {
	return readValidated(path, "")
}

func readValidated(path string, required InputFormat) (Artifact, ValidationResult, error) {
	var result ValidationResult
	raw, err := os.ReadFile(path)
	if err != nil {
		return Artifact{}, result, fieldError("document", "cannot open input")
	}
	top, err := decodeSingleObject(raw)
	if err != nil {
		return Artifact{}, result, err
	}

	_, hasSchema := top["schema"]
	_, hasEntities := top["entities"]
	isWrapper := hasSchema || hasEntities
	if required == FormatRunWrapper && !isWrapper {
		return Artifact{}, result, fieldError("document", "expected run wrapper")
	}
	if required == FormatEntities && isWrapper {
		return Artifact{}, result, fieldError("document", "expected bare entities")
	}
	if isWrapper {
		return decodeRunWrapper(top)
	}
	return decodeBareEntities(top)
}

func decodeRunWrapper(top map[string]json.RawMessage) (Artifact, ValidationResult, error) {
	result := ValidationResult{Format: FormatRunWrapper, Schema: SchemaV1}
	var schema string
	if rawSchema, ok := top["schema"]; !ok {
		return invalid(result, "schema", "missing required version")
	} else if err := json.Unmarshal(rawSchema, &schema); err != nil {
		return invalid(result, "schema", "wrong type")
	} else if strings.TrimSpace(schema) != SchemaV1 {
		return invalid(result, "schema", "unsupported version")
	}

	rawMeta, ok := top["meta"]
	if !ok {
		return invalid(result, "meta", "missing required object")
	}
	if !isJSONObject(rawMeta) {
		return invalid(result, "meta", "wrong type")
	}
	var meta Meta
	if err := json.Unmarshal(rawMeta, &meta); err != nil {
		return invalid(result, jsonTypePath("meta", err), "wrong type")
	}

	rawEntities, ok := top["entities"]
	if !ok {
		return invalid(result, "entities", "missing required object")
	}
	if !isJSONObject(rawEntities) {
		return invalid(result, "entities", "wrong type")
	}
	ent, normalizations, err := decodeEntities(rawEntities, "entities")
	result.Normalizations = normalizations
	result.EntitiesSchema = strings.TrimSpace(ent.SchemaVersion)
	if err != nil {
		return appendIssue(result, err)
	}

	var alerts []zapclient.Alert
	if rawAlerts, ok := top["alerts"]; ok {
		if !isJSONArray(rawAlerts) {
			return invalid(result, "alerts", "wrong collection type")
		}
		if err := json.Unmarshal(rawAlerts, &alerts); err != nil {
			return invalid(result, jsonTypePath("alerts", err), "wrong type")
		}
	}

	if err := validateMetaConsistency(meta, ent); err != nil {
		return appendIssue(result, err)
	}
	entities.FillDerivedRequests(&ent)
	var outcomes *publication.Result
	if raw, ok := top["publication"]; ok && string(raw) != "null" {
		if !isJSONObject(raw) {
			return invalid(result, "publication", "wrong type")
		}
		if err := json.Unmarshal(raw, &outcomes); err != nil {
			return invalid(result, "publication", "wrong type")
		}
	}
	return Artifact{Publication: outcomes, Schema: schema, Meta: meta, Entities: ent, Alerts: alerts}, result, nil
}

func decodeBareEntities(top map[string]json.RawMessage) (Artifact, ValidationResult, error) {
	result := ValidationResult{Format: FormatEntities, Schema: SchemaV1}
	raw, err := json.Marshal(top)
	if err != nil {
		return invalid(result, "document", "invalid JSON object")
	}
	ent, normalizations, err := decodeEntities(raw, "")
	result.Normalizations = normalizations
	result.EntitiesSchema = strings.TrimSpace(ent.SchemaVersion)
	if err != nil {
		return appendIssue(result, err)
	}
	entities.FillDerivedRequests(&ent)
	return Artifact{Schema: SchemaV1, Entities: ent}, result, nil
}

func decodeEntities(raw json.RawMessage, prefix string) (entities.EntitiesFile, []entities.ImportNormalization, error) {
	var ent entities.EntitiesFile
	shape, err := decodeSingleObject(raw)
	if err != nil {
		return ent, nil, withPrefix(prefix, err)
	}
	for _, name := range []string{"definitions", "findings", "occurrences"} {
		path := joinPath(prefix, name)
		collection, ok := shape[name]
		if !ok {
			return ent, nil, fieldError(path, "missing required collection")
		}
		if !isJSONArray(collection) && !isJSONNull(collection) {
			return ent, nil, fieldError(path, "wrong collection type")
		}
	}
	normalized, normalizations, err := entities.NormalizeImportJSONWithReport(raw)
	if err != nil {
		return ent, nil, fieldError(orDocument(prefix), "invalid JSON")
	}
	if prefix != "" {
		for i := range normalizations {
			normalizations[i].Path = joinPath(prefix, normalizations[i].Path)
		}
	}
	if err := json.Unmarshal(normalized, &ent); err != nil {
		return ent, normalizations, fieldError(jsonTypePath(orDocument(prefix), err), "wrong type")
	}
	validation := entities.Validate(ent)
	if !validation.OK() {
		issue := validation.Issues[0]
		issue.Path = joinPath(prefix, issue.Path)
		return ent, normalizations, issue
	}
	return ent, normalizations, nil
}

func validateMetaConsistency(meta Meta, ent entities.EntitiesFile) error {
	if strings.TrimSpace(meta.SourceTool) != "" && strings.TrimSpace(ent.SourceTool) != "" && strings.TrimSpace(meta.SourceTool) != strings.TrimSpace(ent.SourceTool) {
		return fieldError("meta.sourceTool/entities.sourceTool", "inconsistent wrapper metadata")
	}
	if err := validateOptionalTimestamp("meta.generatedAt", meta.GeneratedAt); err != nil {
		return err
	}
	if strings.TrimSpace(meta.GeneratedAt) != "" && strings.TrimSpace(ent.GeneratedAt) != "" {
		metaTime, metaErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(meta.GeneratedAt))
		entityTime, entityErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(ent.GeneratedAt))
		if metaErr == nil && entityErr == nil && !metaTime.Equal(entityTime) {
			return fieldError("meta.generatedAt/entities.generatedAt", "inconsistent wrapper metadata")
		}
	}
	return nil
}

func validateOptionalTimestamp(path, value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	if _, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value)); err != nil {
		return fieldError(path, "invalid RFC3339 timestamp")
	}
	return nil
}

func decodeSingleObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var object map[string]json.RawMessage
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, fieldError("document", "invalid JSON object")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fieldError("document", "trailing JSON value")
		}
		return nil, fieldError("document", "invalid trailing JSON")
	}
	return object, nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{'
}

func isJSONArray(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '['
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func jsonTypePath(prefix string, err error) string {
	typeErr, ok := err.(*json.UnmarshalTypeError)
	if ok && strings.TrimSpace(typeErr.Field) != "" {
		return joinPath(prefix, typeErr.Field)
	}
	return prefix
}

func invalid(result ValidationResult, path, category string) (Artifact, ValidationResult, error) {
	issue := fieldError(path, category)
	result.Issues = append(result.Issues, issue)
	return Artifact{}, result, issue
}

func appendIssue(result ValidationResult, err error) (Artifact, ValidationResult, error) {
	if issue, ok := err.(entities.ValidationIssue); ok {
		result.Issues = append(result.Issues, issue)
	}
	return Artifact{}, result, err
}

func fieldError(path, category string) entities.ValidationIssue {
	return entities.ValidationIssue{Path: path, Category: category}
}

func withPrefix(prefix string, err error) error {
	issue, ok := err.(entities.ValidationIssue)
	if !ok || prefix == "" {
		return err
	}
	issue.Path = joinPath(prefix, issue.Path)
	return issue
}

func joinPath(prefix, path string) string {
	if prefix == "" {
		return path
	}
	if path == "" || path == "document" {
		return prefix
	}
	return prefix + "." + path
}

func orDocument(path string) string {
	if path == "" {
		return "document"
	}
	return path
}
