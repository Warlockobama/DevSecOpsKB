package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/entities"
	"github.com/Warlockobama/DevSecOpsKB/zap-kb/internal/output/runartifact"
)

const defaultAttackSTIXURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
const defaultCWEXMLZipURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
const defaultCAPECXMLURL = "https://capec.mitre.org/data/xml/capec_latest.xml"

type taxonomyAuditRow struct {
	DefinitionID string `json:"definitionId"`
	PluginID     string `json:"pluginId"`
	Title        string `json:"title,omitempty"`
	CWEID        int    `json:"cweid,omitempty"`
	HasCWE       bool   `json:"hasCwe"`
	HasOWASP     bool   `json:"hasOwasp"`
	HasCAPEC     bool   `json:"hasCapec"`
	HasATTACK    bool   `json:"hasAttack"`
}

type taxonomyAuditSummary struct {
	Definitions int                `json:"definitions"`
	CWE         int                `json:"cwe"`
	OWASP       int                `json:"owasp"`
	CAPEC       int                `json:"capec"`
	ATTACK      int                `json:"attack"`
	Missing     []taxonomyAuditRow `json:"missing"`
}

type capecCandidateRow struct {
	DefinitionID string           `json:"definitionId"`
	PluginID     string           `json:"pluginId"`
	Title        string           `json:"title,omitempty"`
	CWEID        int              `json:"cweid"`
	Candidates   []capecCandidate `json:"candidates"`
}

type capecCandidate struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Status string `json:"status,omitempty"`
}

type attackTechniqueCache struct {
	Schema      string            `json:"schema"`
	GeneratedAt string            `json:"generatedAt"`
	SourceURL   string            `json:"sourceUrl"`
	Techniques  []attackTechnique `json:"techniques"`
}

type attackTechnique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url,omitempty"`
	Tactics []string `json:"tactics,omitempty"`
}

type cweCache struct {
	Schema      string        `json:"schema"`
	GeneratedAt string        `json:"generatedAt"`
	SourceURL   string        `json:"sourceUrl"`
	Version     string        `json:"version,omitempty"`
	Date        string        `json:"date,omitempty"`
	Weaknesses  []cweWeakness `json:"weaknesses"`
}

type cweWeakness struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	URL               string `json:"url"`
	Status            string `json:"status,omitempty"`
	RelatedWeaknesses []int  `json:"relatedWeaknesses,omitempty"`
}

type capecCache struct {
	Schema         string               `json:"schema"`
	GeneratedAt    string               `json:"generatedAt"`
	SourceURL      string               `json:"sourceUrl"`
	Version        string               `json:"version,omitempty"`
	Date           string               `json:"date,omitempty"`
	AttackPatterns []capecAttackPattern `json:"attackPatterns"`
}

type capecAttackPattern struct {
	ID                int      `json:"id"`
	Name              string   `json:"name"`
	URL               string   `json:"url"`
	Status            string   `json:"status,omitempty"`
	RelatedWeaknesses []int    `json:"relatedWeaknesses,omitempty"`
	RelatedATTACKIDs  []string `json:"relatedAttackIds,omitempty"`
}

func runTaxonomyCommand(args []string) {
	if len(args) == 0 {
		taxonomyUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "audit":
		runTaxonomyAudit(args[1:])
	case "update":
		runTaxonomyUpdate(args[1:])
	case "suggest-capec":
		runTaxonomySuggestCAPEC(args[1:])
	case "-h", "--help", "help":
		taxonomyUsage()
	default:
		fmt.Fprintf(os.Stderr, "taxonomy: unknown subcommand %q\n", args[0])
		taxonomyUsage()
		os.Exit(2)
	}
}

func taxonomyUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  zap-kb taxonomy audit -entities-in PATH [-json]
      Report CWE/OWASP/CAPEC/ATT&CK coverage for definitions.

  zap-kb taxonomy update -source attack [-url URL] -out PATH
      Fetch MITRE ATT&CK STIX technique metadata into a local cache.
  zap-kb taxonomy update -source cwe [-url URL] -out PATH
      Fetch MITRE CWE XML ZIP metadata into a local cache.
  zap-kb taxonomy update -source capec [-url URL] -out PATH
      Fetch MITRE CAPEC XML metadata into a local cache.
  zap-kb taxonomy suggest-capec -entities-in PATH -capec-cache PATH [-json]
      Suggest candidate CAPEC mappings for definitions with CWE IDs.

Normal KB enrichment remains offline; update commands refresh local inputs explicitly.`)
}

func runTaxonomyAudit(args []string) {
	fs := flag.NewFlagSet("taxonomy audit", flag.ExitOnError)
	var entitiesIn string
	var jsonOut bool
	fs.StringVar(&entitiesIn, "entities-in", "", "Entities JSON or run artifact to audit")
	fs.BoolVar(&jsonOut, "json", false, "Emit JSON instead of text")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "taxonomy audit: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(entitiesIn) == "" {
		fmt.Fprintln(os.Stderr, "taxonomy audit: -entities-in is required")
		os.Exit(2)
	}
	art, err := runartifact.ReadFlexible(strings.TrimSpace(entitiesIn))
	if err != nil {
		fmt.Fprintf(os.Stderr, "taxonomy audit: read %q: %v\n", entitiesIn, err)
		os.Exit(1)
	}
	summary := buildTaxonomyAudit(art.Entities)
	if jsonOut {
		enc, err := json.MarshalIndent(summary, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "taxonomy audit: encode: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(enc)
		os.Stdout.WriteString("\n")
		return
	}
	fmt.Printf("Definitions: %d\n", summary.Definitions)
	fmt.Printf("CWE: %d/%d\n", summary.CWE, summary.Definitions)
	fmt.Printf("OWASP: %d/%d\n", summary.OWASP, summary.Definitions)
	fmt.Printf("CAPEC: %d/%d\n", summary.CAPEC, summary.Definitions)
	fmt.Printf("ATT&CK: %d/%d\n", summary.ATTACK, summary.Definitions)
	if len(summary.Missing) > 0 {
		fmt.Println("Missing taxonomy:")
		for _, row := range summary.Missing {
			var gaps []string
			if !row.HasCWE {
				gaps = append(gaps, "CWE")
			}
			if !row.HasOWASP {
				gaps = append(gaps, "OWASP")
			}
			if !row.HasCAPEC {
				gaps = append(gaps, "CAPEC")
			}
			if !row.HasATTACK {
				gaps = append(gaps, "ATT&CK")
			}
			fmt.Printf("- %s plugin=%s gaps=%s title=%s\n", row.DefinitionID, row.PluginID, strings.Join(gaps, ","), row.Title)
		}
	}
}

func buildTaxonomyAudit(ef entities.EntitiesFile) taxonomyAuditSummary {
	rows := make([]taxonomyAuditRow, 0)
	var summary taxonomyAuditSummary
	for _, def := range ef.Definitions {
		summary.Definitions++
		row := taxonomyAuditRow{
			DefinitionID: strings.TrimSpace(def.DefinitionID),
			PluginID:     strings.TrimSpace(def.PluginID),
			Title:        firstNonEmpty(def.Alert, def.Name),
		}
		if def.Taxonomy != nil {
			row.CWEID = def.Taxonomy.CWEID
			row.HasCWE = def.Taxonomy.CWEID > 0 || strings.TrimSpace(def.Taxonomy.CWEURI) != ""
			row.HasOWASP = len(def.Taxonomy.OWASPTop10) > 0
			row.HasCAPEC = len(def.Taxonomy.CAPECIDs) > 0 || len(def.Taxonomy.CAPEC) > 0
			row.HasATTACK = len(def.Taxonomy.ATTACK) > 0 || len(def.Taxonomy.ATTACKTechniques) > 0
		}
		if row.HasCWE {
			summary.CWE++
		}
		if row.HasOWASP {
			summary.OWASP++
		}
		if row.HasCAPEC {
			summary.CAPEC++
		}
		if row.HasATTACK {
			summary.ATTACK++
		}
		if !row.HasCWE || !row.HasOWASP || !row.HasCAPEC || !row.HasATTACK {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].PluginID != rows[j].PluginID {
			return rows[i].PluginID < rows[j].PluginID
		}
		return rows[i].DefinitionID < rows[j].DefinitionID
	})
	summary.Missing = rows
	return summary
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func runTaxonomyUpdate(args []string) {
	fs := flag.NewFlagSet("taxonomy update", flag.ExitOnError)
	var source string
	var out string
	var sourceURL string
	fs.StringVar(&source, "source", "attack", "Source to update: attack")
	fs.StringVar(&out, "out", "", "Output cache JSON path")
	fs.StringVar(&sourceURL, "url", "", "Source URL for the selected catalog")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "taxonomy update: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(out) == "" {
		fmt.Fprintln(os.Stderr, "taxonomy update: -out is required")
		os.Exit(2)
	}
	if strings.TrimSpace(sourceURL) == "" {
		sourceURL = defaultTaxonomySourceURL(source)
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "attack":
		cache, err := fetchAttackTechniqueCache(strings.TrimSpace(sourceURL))
		if err != nil {
			fmt.Fprintf(os.Stderr, "taxonomy update: attack: %v\n", err)
			os.Exit(1)
		}
		if err := writeJSONFile(out, cache); err != nil {
			fmt.Fprintf(os.Stderr, "taxonomy update: write %q: %v\n", out, err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %d ATT&CK techniques to %s\n", len(cache.Techniques), out)
	case "cwe":
		cache, err := fetchCWECache(strings.TrimSpace(sourceURL))
		if err != nil {
			fmt.Fprintf(os.Stderr, "taxonomy update: cwe: %v\n", err)
			os.Exit(1)
		}
		if err := writeJSONFile(out, cache); err != nil {
			fmt.Fprintf(os.Stderr, "taxonomy update: write %q: %v\n", out, err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %d CWE weaknesses to %s\n", len(cache.Weaknesses), out)
	case "capec":
		cache, err := fetchCAPECCache(strings.TrimSpace(sourceURL))
		if err != nil {
			fmt.Fprintf(os.Stderr, "taxonomy update: capec: %v\n", err)
			os.Exit(1)
		}
		if err := writeJSONFile(out, cache); err != nil {
			fmt.Fprintf(os.Stderr, "taxonomy update: write %q: %v\n", out, err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %d CAPEC attack patterns to %s\n", len(cache.AttackPatterns), out)
	default:
		fmt.Fprintf(os.Stderr, "taxonomy update: unsupported source %q\n", source)
		os.Exit(2)
	}
}

func runTaxonomySuggestCAPEC(args []string) {
	fs := flag.NewFlagSet("taxonomy suggest-capec", flag.ExitOnError)
	var entitiesIn string
	var capecCachePath string
	var jsonOut bool
	fs.StringVar(&entitiesIn, "entities-in", "", "Entities JSON or run artifact to inspect")
	fs.StringVar(&capecCachePath, "capec-cache", "", "CAPEC cache JSON from taxonomy update -source capec")
	fs.BoolVar(&jsonOut, "json", false, "Emit JSON instead of text")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "taxonomy suggest-capec: %v\n", err)
		os.Exit(1)
	}
	if strings.TrimSpace(entitiesIn) == "" || strings.TrimSpace(capecCachePath) == "" {
		fmt.Fprintln(os.Stderr, "taxonomy suggest-capec: -entities-in and -capec-cache are required")
		os.Exit(2)
	}
	art, err := runartifact.ReadFlexible(strings.TrimSpace(entitiesIn))
	if err != nil {
		fmt.Fprintf(os.Stderr, "taxonomy suggest-capec: read entities %q: %v\n", entitiesIn, err)
		os.Exit(1)
	}
	cache, err := readCAPECCache(capecCachePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taxonomy suggest-capec: read capec cache %q: %v\n", capecCachePath, err)
		os.Exit(1)
	}
	rows := buildCAPECCandidates(art.Entities, cache)
	if jsonOut {
		enc, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "taxonomy suggest-capec: encode: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(enc)
		os.Stdout.WriteString("\n")
		return
	}
	fmt.Printf("Definitions with CAPEC candidates: %d\n", len(rows))
	for _, row := range rows {
		parts := make([]string, 0, len(row.Candidates))
		for _, candidate := range row.Candidates {
			parts = append(parts, fmt.Sprintf("CAPEC-%d %s", candidate.ID, candidate.Name))
		}
		fmt.Printf("- %s plugin=%s CWE-%d candidates=%s\n", row.DefinitionID, row.PluginID, row.CWEID, strings.Join(parts, "; "))
	}
}

func readCAPECCache(path string) (capecCache, error) {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return capecCache{}, err
	}
	var cache capecCache
	if err := json.Unmarshal(raw, &cache); err != nil {
		return capecCache{}, err
	}
	return cache, nil
}

func buildCAPECCandidates(ef entities.EntitiesFile, cache capecCache) []capecCandidateRow {
	byCWE := map[int][]capecCandidate{}
	for _, pattern := range cache.AttackPatterns {
		for _, cweID := range pattern.RelatedWeaknesses {
			if cweID <= 0 {
				continue
			}
			byCWE[cweID] = append(byCWE[cweID], capecCandidate{
				ID:     pattern.ID,
				Name:   pattern.Name,
				URL:    pattern.URL,
				Status: pattern.Status,
			})
		}
	}
	for cweID := range byCWE {
		sort.Slice(byCWE[cweID], func(i, j int) bool { return byCWE[cweID][i].ID < byCWE[cweID][j].ID })
	}
	rows := make([]capecCandidateRow, 0)
	for _, def := range ef.Definitions {
		if def.Taxonomy == nil || def.Taxonomy.CWEID <= 0 {
			continue
		}
		candidates := byCWE[def.Taxonomy.CWEID]
		if len(candidates) == 0 {
			continue
		}
		rows = append(rows, capecCandidateRow{
			DefinitionID: strings.TrimSpace(def.DefinitionID),
			PluginID:     strings.TrimSpace(def.PluginID),
			Title:        firstNonEmpty(def.Alert, def.Name),
			CWEID:        def.Taxonomy.CWEID,
			Candidates:   candidates,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].PluginID != rows[j].PluginID {
			return rows[i].PluginID < rows[j].PluginID
		}
		return rows[i].DefinitionID < rows[j].DefinitionID
	})
	return rows
}

func defaultTaxonomySourceURL(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "attack":
		return defaultAttackSTIXURL
	case "cwe":
		return defaultCWEXMLZipURL
	case "capec":
		return defaultCAPECXMLURL
	default:
		return ""
	}
}

func fetchAttackTechniqueCache(sourceURL string) (attackTechniqueCache, error) {
	if strings.TrimSpace(sourceURL) == "" {
		return attackTechniqueCache{}, fmt.Errorf("source URL is required")
	}
	raw, err := fetchURLBytes(sourceURL, "application/json", 200*1024*1024)
	if err != nil {
		return attackTechniqueCache{}, err
	}
	techniques, err := parseAttackTechniques(raw)
	if err != nil {
		return attackTechniqueCache{}, err
	}
	return attackTechniqueCache{
		Schema:      "devsecopskb/attack-technique-cache/v1",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SourceURL:   sourceURL,
		Techniques:  techniques,
	}, nil
}

func fetchCWECache(sourceURL string) (cweCache, error) {
	raw, err := fetchURLBytes(sourceURL, "application/zip, application/xml, text/xml", 200*1024*1024)
	if err != nil {
		return cweCache{}, err
	}
	xmlData := raw
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(sourceURL)), ".zip") {
		xmlData, err = firstXMLFromZip(raw)
		if err != nil {
			return cweCache{}, err
		}
	}
	version, date, weaknesses, err := parseCWEWeaknesses(xmlData)
	if err != nil {
		return cweCache{}, err
	}
	return cweCache{
		Schema:      "devsecopskb/cwe-cache/v1",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		SourceURL:   sourceURL,
		Version:     version,
		Date:        date,
		Weaknesses:  weaknesses,
	}, nil
}

func fetchCAPECCache(sourceURL string) (capecCache, error) {
	raw, err := fetchURLBytes(sourceURL, "application/xml, text/xml, application/zip", 200*1024*1024)
	if err != nil {
		return capecCache{}, err
	}
	xmlData := raw
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(sourceURL)), ".zip") {
		xmlData, err = firstXMLFromZip(raw)
		if err != nil {
			return capecCache{}, err
		}
	}
	version, date, patterns, err := parseCAPECAttackPatterns(xmlData)
	if err != nil {
		return capecCache{}, err
	}
	return capecCache{
		Schema:         "devsecopskb/capec-cache/v1",
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		SourceURL:      sourceURL,
		Version:        version,
		Date:           date,
		AttackPatterns: patterns,
	}, nil
}

func fetchURLBytes(sourceURL, accept string, limit int64) ([]byte, error) {
	if strings.TrimSpace(sourceURL) == "" {
		return nil, fmt.Errorf("source URL is required")
	}
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(accept) != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("GET %s: status=%d body=%s", sourceURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func firstXMLFromZip(raw []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	for _, file := range zr.File {
		if !strings.HasSuffix(strings.ToLower(file.Name), ".xml") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, 200*1024*1024))
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return data, nil
	}
	return nil, fmt.Errorf("zip archive contains no XML file")
}

func parseAttackTechniques(raw []byte) ([]attackTechnique, error) {
	var bundle struct {
		Objects []struct {
			Type               string `json:"type"`
			Name               string `json:"name"`
			Revoked            bool   `json:"revoked"`
			XMITREDeprecated   bool   `json:"x_mitre_deprecated"`
			ExternalReferences []struct {
				SourceName string `json:"source_name"`
				ExternalID string `json:"external_id"`
				URL        string `json:"url"`
			} `json:"external_references"`
			KillChainPhases []struct {
				KillChainName string `json:"kill_chain_name"`
				PhaseName     string `json:"phase_name"`
			} `json:"kill_chain_phases"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, err
	}
	techniques := make([]attackTechnique, 0)
	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" || obj.Revoked || obj.XMITREDeprecated {
			continue
		}
		id, url := "", ""
		for _, ref := range obj.ExternalReferences {
			if strings.EqualFold(strings.TrimSpace(ref.SourceName), "mitre-attack") && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(ref.ExternalID)), "T") {
				id = strings.ToUpper(strings.TrimSpace(ref.ExternalID))
				url = strings.TrimSpace(ref.URL)
				break
			}
		}
		if id == "" {
			continue
		}
		tactics := make([]string, 0)
		seenTactics := map[string]struct{}{}
		for _, phase := range obj.KillChainPhases {
			if !strings.EqualFold(strings.TrimSpace(phase.KillChainName), "mitre-attack") {
				continue
			}
			tactic := strings.TrimSpace(phase.PhaseName)
			if tactic == "" {
				continue
			}
			if _, ok := seenTactics[tactic]; ok {
				continue
			}
			seenTactics[tactic] = struct{}{}
			tactics = append(tactics, tactic)
		}
		sort.Strings(tactics)
		techniques = append(techniques, attackTechnique{
			ID:      id,
			Name:    strings.TrimSpace(obj.Name),
			URL:     url,
			Tactics: tactics,
		})
	}
	sort.Slice(techniques, func(i, j int) bool { return techniques[i].ID < techniques[j].ID })
	return techniques, nil
}

func parseCWEWeaknesses(raw []byte) (string, string, []cweWeakness, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	version, date := "", ""
	weaknesses := make([]cweWeakness, 0)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", nil, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "Weakness_Catalog":
			version = xmlAttr(start, "Version")
			date = xmlAttr(start, "Date")
		case "Weakness":
			w, err := decodeCWEWeakness(dec, start)
			if err != nil {
				return "", "", nil, err
			}
			if w.ID > 0 {
				weaknesses = append(weaknesses, w)
			}
		}
	}
	sort.Slice(weaknesses, func(i, j int) bool { return weaknesses[i].ID < weaknesses[j].ID })
	return version, date, weaknesses, nil
}

func decodeCWEWeakness(dec *xml.Decoder, start xml.StartElement) (cweWeakness, error) {
	id := atoiSafe(xmlAttr(start, "ID"))
	w := cweWeakness{
		ID:     id,
		Name:   strings.TrimSpace(xmlAttr(start, "Name")),
		URL:    fmt.Sprintf("https://cwe.mitre.org/data/definitions/%d.html", id),
		Status: strings.TrimSpace(xmlAttr(start, "Status")),
	}
	seenRelated := map[int]struct{}{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return w, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "Related_Weakness" {
				relatedID := atoiSafe(xmlAttr(t, "CWE_ID"))
				if relatedID > 0 {
					seenRelated[relatedID] = struct{}{}
				}
			}
		case xml.EndElement:
			if t.Name.Local == start.Name.Local {
				for relatedID := range seenRelated {
					w.RelatedWeaknesses = append(w.RelatedWeaknesses, relatedID)
				}
				sort.Ints(w.RelatedWeaknesses)
				return w, nil
			}
		}
	}
}

func parseCAPECAttackPatterns(raw []byte) (string, string, []capecAttackPattern, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	version, date := "", ""
	patterns := make([]capecAttackPattern, 0)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", nil, err
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "Attack_Pattern_Catalog":
			version = xmlAttr(start, "Version")
			date = xmlAttr(start, "Date")
		case "Attack_Pattern":
			p, err := decodeCAPECAttackPattern(dec, start)
			if err != nil {
				return "", "", nil, err
			}
			if p.ID > 0 {
				patterns = append(patterns, p)
			}
		}
	}
	sort.Slice(patterns, func(i, j int) bool { return patterns[i].ID < patterns[j].ID })
	return version, date, patterns, nil
}

func decodeCAPECAttackPattern(dec *xml.Decoder, start xml.StartElement) (capecAttackPattern, error) {
	id := atoiSafe(xmlAttr(start, "ID"))
	p := capecAttackPattern{
		ID:     id,
		Name:   strings.TrimSpace(xmlAttr(start, "Name")),
		URL:    fmt.Sprintf("https://capec.mitre.org/data/definitions/%d.html", id),
		Status: strings.TrimSpace(xmlAttr(start, "Status")),
	}
	seenCWE := map[int]struct{}{}
	seenAttack := map[string]struct{}{}
	for {
		tok, err := dec.Token()
		if err != nil {
			return p, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Related_Weakness":
				cweID := atoiSafe(xmlAttr(t, "CWE_ID"))
				if cweID > 0 {
					seenCWE[cweID] = struct{}{}
				}
			case "External_Reference":
				attackID := strings.ToUpper(strings.TrimSpace(xmlAttr(t, "External_ID")))
				if strings.HasPrefix(attackID, "T") {
					seenAttack[attackID] = struct{}{}
				}
			}
		case xml.EndElement:
			if t.Name.Local == start.Name.Local {
				for cweID := range seenCWE {
					p.RelatedWeaknesses = append(p.RelatedWeaknesses, cweID)
				}
				sort.Ints(p.RelatedWeaknesses)
				for attackID := range seenAttack {
					p.RelatedATTACKIDs = append(p.RelatedATTACKIDs, attackID)
				}
				sort.Strings(p.RelatedATTACKIDs)
				return p, nil
			}
		}
	}
}

func xmlAttr(start xml.StartElement, local string) string {
	for _, attr := range start.Attr {
		if attr.Name.Local == local {
			return attr.Value
		}
	}
	return ""
}

func atoiSafe(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	var out int
	if _, err := fmt.Sscanf(raw, "%d", &out); err != nil {
		return 0
	}
	return out
}

func writeJSONFile(path string, v any) error {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
