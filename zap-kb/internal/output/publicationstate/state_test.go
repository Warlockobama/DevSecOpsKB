package publicationstate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

func fixture() entities.EntitiesFile {
	return entities.EntitiesFile{SchemaVersion: "v1", SourceTool: "zap", Definitions: []entities.Definition{{DefinitionID: "d1", PluginID: "1"}}, Findings: []entities.Finding{{FindingID: "f1", DefinitionID: "d1", PluginID: "1", URL: "https://example.test", Method: "GET", Analyst: &entities.Analyst{Status: "in_progress", Owner: "analyst"}}}, Occurrences: []entities.Occurrence{{OccurrenceID: "o1", FindingID: "f1", DefinitionID: "d1", URL: "https://example.test", Method: "GET"}}}
}
func TestOldPublisherSnapshotCannotOverwriteNewHandoff(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "entities.json")
	before := fixture()
	raw, _ := json.Marshal(before)
	if err := os.WriteFile(input, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Public validator reads A. A producer atomically replaces it with B while
	// the mocked remote create response is held on a channel.
	a, _, err := runartifact.ReadValidated(input)
	if err != nil {
		t.Fatal(err)
	}
	response := make(chan struct{})
	finished := make(chan error, 1)
	s := Store{Dir: filepath.Join(dir, "state")}
	dest := Destination("jira", "https://jira.example", "TEST")
	go func() {
		<-response
		finished <- s.Record(dest, a.Entities, map[string]string{"f1": "TEST-1"}, nil, publication.Result{Stages: []publication.StageResult{{Destination: "jira", Stage: "issues", Status: publication.Successful, Succeeded: 1}}})
	}()
	newer := fixture()
	newer.Occurrences = append(newer.Occurrences, entities.Occurrence{OccurrenceID: "o2", FindingID: "f1", DefinitionID: "d1", URL: "https://example.test/new", Method: "GET"})
	newRaw, _ := json.Marshal(newer)
	tmp := input + ".next"
	os.WriteFile(tmp, newRaw, 0600)
	if err := os.Rename(tmp, input); err != nil {
		t.Fatal(err)
	}
	close(response)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(input)
	if string(got) != string(newRaw) {
		t.Fatal("publisher changed producer bytes")
	}
	b, _, err := runartifact.ReadValidated(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Apply(dest, &b.Entities); err != nil {
		t.Fatal(err)
	}
	if len(b.Entities.Occurrences) != 2 || len(b.Entities.Findings[0].Analyst.TicketRefs) != 1 {
		t.Fatalf("lost evidence or refs: %+v", b.Entities)
	}
	if b.Entities.Findings[0].Analyst.Owner != "analyst" || b.Entities.Findings[0].Analyst.Status != "in_progress" {
		t.Fatal("analyst ownership changed")
	}
}
func TestConcurrentPartialDestinationsRestartAndCorruption(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	dest := Destination("jira", "https://jira.example", "TEST")
	other := Destination("jira", "https://other.example", "TEST")
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Record(dest, fixture(), map[string]string{"f1": "TEST-1"}, nil, publication.Result{Stages: []publication.StageResult{{Destination: "jira", Stage: "issues", Status: publication.Successful, Succeeded: 1}, {Destination: "confluence", Stage: "wiki", Status: publication.Failed, Failed: 1, Diagnostics: []publication.Diagnostic{{Message: "SECRET synthetic remote body"}}}}})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(s.Dir, dest, "*.json"))
	if len(files) != 20 {
		t.Fatalf("lost concurrent records: %d", len(files))
	}
	for _, p := range files {
		raw, _ := os.ReadFile(p)
		if strings.Contains(string(raw), "SECRET") {
			t.Fatal("persisted remote diagnostic")
		}
	}
	v := fixture()
	if err := (Store{Dir: s.Dir}).Apply(dest, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Findings[0].Analyst.TicketRefs) != 1 {
		t.Fatal("retry did not converge")
	}
	foreign := fixture()
	if err := s.Apply(other, &foreign); err != nil {
		t.Fatal(err)
	}
	if len(foreign.Findings[0].Analyst.TicketRefs) != 0 {
		t.Fatal("cross-destination refs")
	}
	stale := fixture()
	stale.Findings[0].FindingID = "new-finding"
	stale.Occurrences[0].FindingID = "new-finding"
	if err := s.Apply(dest, &stale); err != nil {
		t.Fatal(err)
	}
	if len(stale.Findings[0].Analyst.TicketRefs) != 0 {
		t.Fatal("wrong identity received ref")
	}
	os.WriteFile(filepath.Join(s.Dir, dest, "corrupt.json"), []byte("{"), 0600)
	unchanged := fixture()
	raw, _ := json.Marshal(unchanged)
	if err := s.Apply(dest, &unchanged); err == nil {
		t.Fatal("accepted malformed state")
	}
	after, _ := json.Marshal(unchanged)
	if string(raw) != string(after) {
		t.Fatal("partially mutated before rejection")
	}
}
func TestDefinitionMismatchAndLegacyRefs(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	dest := Destination("forgejo", "https://forgejo.example", "o/r")
	v := fixture()
	v.Findings[0].Analyst.TicketRefs = []string{"LEGACY-9"}
	if err := s.Record(dest, v, map[string]string{"f1": "o/r#42"}, nil, publication.Result{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(dest, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Findings[0].Analyst.TicketRefs) != 2 {
		t.Fatal("legacy reference lost")
	}
	v.Definitions[0].DefinitionID = "d2"
	v.Findings[0].DefinitionID = "d2"
	v.Occurrences[0].DefinitionID = "d2"
	if err := s.Apply(dest, &v); err == nil {
		t.Fatal("accepted finding/definition identity drift")
	}
	if err := s.Record(dest, fixture(), map[string]string{"missing": "TEST-2"}, nil, publication.Result{}); err == nil {
		t.Fatal("accepted unknown finding")
	}
}
