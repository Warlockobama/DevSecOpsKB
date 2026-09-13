// Package publicationstate stores publication references separately from immutable
// scanner input. Each operation appends an atomic event; concurrent publishers
// never truncate one another's state or rewrite producer-owned evidence.
package publicationstate

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/publication"
)

const schema = "zap-kb/publication-state/v1"

type Store struct{ Dir string }
type reference struct {
	FindingID    string `json:"findingId"`
	DefinitionID string `json:"definitionId"`
	Ref          string `json:"ref"`
}
type event struct {
	Schema      string             `json:"schema"`
	Destination string             `json:"destination"`
	InputDigest string             `json:"inputDigest"`
	References  []reference        `json:"references,omitempty"`
	Epics       map[string]string  `json:"epics,omitempty"`
	Result      publication.Result `json:"result"`
}

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var refRE = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9_]*-[0-9]+|[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[0-9]+)$`)

// Destination isolates trackers, hosts, and projects without putting endpoint
// URLs or their credentials in filenames or state. Supply a credential-free URL.
func Destination(kind, baseURL, scope string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(kind)+"\n"+strings.TrimRight(strings.TrimSpace(baseURL), "/")+"\n"+strings.TrimSpace(scope))))
}

// Record stores confirmed references even when another required stage failed.
// Callers pass only exporter-confirmed references, never inferred create IDs.
// Typed validation is the same entities validator used by runartifact ingestion.
// Diagnostics are intentionally excluded: durable state needs outcomes, not text.
func (s Store) Record(destination string, input entities.EntitiesFile, refs, epics map[string]string, result publication.Result) error {
	if err := entities.Validate(input).Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	e := event{Schema: schema, Destination: destination, InputDigest: fmt.Sprintf("%x", sha256.Sum256(raw)), Epics: epics}
	findings := map[string]string{}
	defs := map[string]bool{}
	for _, d := range input.Definitions {
		defs[d.DefinitionID] = true
	}
	for _, f := range input.Findings {
		findings[f.FindingID] = f.DefinitionID
	}
	for id, ref := range refs {
		def, ok := findings[id]
		if !ok {
			return errors.New("publication state: unknown finding")
		}
		e.References = append(e.References, reference{id, def, ref})
	}
	for id := range epics {
		if !defs[id] {
			return errors.New("publication state: unknown definition")
		}
	}
	sort.Slice(e.References, func(i, j int) bool { return e.References[i].FindingID < e.References[j].FindingID })
	for _, stage := range result.Stages {
		stage.Diagnostics = nil
		e.Result.Stages = append(e.Result.Stages, stage)
	}
	if err := validate(e); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Join(s.Dir, destination)
	if s.Dir == "" {
		return errors.New("publication state: directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("publication state: cannot create directory")
	}
	f, err := os.CreateTemp(dir, ".pending-*")
	if err != nil {
		return errors.New("publication state: cannot create event")
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return errors.New("publication state: cannot write event")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return errors.New("publication state: cannot sync event")
	}
	if err = f.Close(); err != nil {
		return errors.New("publication state: cannot close event")
	}
	if err = os.Rename(name, filepath.Join(dir, filepath.Base(name)+".json")); err != nil {
		return errors.New("publication state: cannot commit event")
	}
	return nil
}

// Apply overlays only ticket/epic references onto matching validated identities.
// It never copies status, assignee, suppression, evidence, or workflow history.
// It reads and validates every event before changing the supplied entities.
// Conflicting epic IDs fail closed; finding references are unioned for remote
// reconciliation, preserving all confirmed IDs after concurrent partial results.
func (s Store) Apply(destination string, input *entities.EntitiesFile) error {
	if s.Dir == "" {
		return errors.New("publication state: directory required")
	}
	if input == nil {
		return errors.New("publication state: input required")
	}
	if !digestRE.MatchString(destination) {
		return errors.New("publication state: invalid destination")
	}
	if err := entities.Validate(*input).Err(); err != nil {
		return err
	}
	paths, err := filepath.Glob(filepath.Join(s.Dir, destination, "*.json"))
	if err != nil {
		return err
	}
	var events []event
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return errors.New("publication state: cannot read event")
		}
		decoder := json.NewDecoder(io.LimitReader(f, 16<<20))
		decoder.DisallowUnknownFields()
		var e event
		err = decoder.Decode(&e)
		if err == nil {
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				err = errors.New("trailing data")
			}
		}
		f.Close()
		if err != nil {
			return errors.New("publication state: invalid event")
		}
		if err = validate(e); err != nil {
			return err
		}
		if e.Destination != destination {
			return errors.New("publication state: destination mismatch")
		}
		events = append(events, e)
	}
	raw, _ := json.Marshal(input)
	var next entities.EntitiesFile
	if err = json.Unmarshal(raw, &next); err != nil {
		return err
	}
	findings := map[string]*entities.Finding{}
	defs := map[string]*entities.Definition{}
	for i := range next.Findings {
		findings[next.Findings[i].FindingID] = &next.Findings[i]
	}
	for i := range next.Definitions {
		defs[next.Definitions[i].DefinitionID] = &next.Definitions[i]
	}
	for _, e := range events {
		for _, r := range e.References {
			f, ok := findings[r.FindingID]
			if !ok {
				continue
			}
			if f.DefinitionID != r.DefinitionID {
				return errors.New("publication state: finding definition mismatch")
			}
			if f.Analyst == nil {
				f.Analyst = &entities.Analyst{}
			}
			found := false
			for _, ref := range f.Analyst.TicketRefs {
				if ref == r.Ref {
					found = true
				}
			}
			if !found {
				f.Analyst.TicketRefs = append(f.Analyst.TicketRefs, r.Ref)
			}
		}
		for id, ref := range e.Epics {
			if d, ok := defs[id]; ok {
				if d.EpicRef != "" && d.EpicRef != ref {
					return errors.New("publication state: conflicting epic references")
				}
				d.EpicRef = ref
			}
		}
	}
	*input = next
	return nil
}

func validate(e event) error {
	if e.Schema != schema || !digestRE.MatchString(e.Destination) || !digestRE.MatchString(e.InputDigest) {
		return errors.New("publication state: invalid event identity")
	}
	for _, r := range e.References {
		if r.FindingID == "" || r.DefinitionID == "" || !refRE.MatchString(r.Ref) {
			return errors.New("publication state: invalid reference")
		}
	}
	for id, ref := range e.Epics {
		if id == "" || !refRE.MatchString(ref) {
			return errors.New("publication state: invalid epic")
		}
	}
	for _, s := range e.Result.Stages {
		switch s.Status {
		case publication.Successful, publication.Partial, publication.Failed, publication.Skipped:
		default:
			return errors.New("publication state: invalid stage outcome")
		}
		if s.Attempted < 0 || s.Succeeded < 0 || s.Skipped < 0 || s.Failed < 0 || len(s.Diagnostics) > 0 {
			return errors.New("publication state: invalid stage counts")
		}
	}
	return nil
}
